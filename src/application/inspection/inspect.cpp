#include "application/inspection/inspect.hpp"

#include "application/concurrency.hpp"
#include "application/detail.hpp"
#include "application/history_storage/activity.hpp"
#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/detail.hpp"
#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/history.hpp"
#include "application/progress.hpp"
#include "core/node.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/pack.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/cancellation.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"
#include "platform/workspace.hpp"
#include "runtime/resolver.hpp"
#include "runtime/vault.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <deque>
#include <exception>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace kasumi::application {
namespace {

struct InspectionContext {
    runtime::RuntimeData runtime;
    runtime::vault::KeyBytes key{};
    history_storage::RemoteLayout layout{};
    transport::Transport storage{};
    std::optional<platform::Workspace> workspace;
    observation::history::ObservationHints hints;
    ProgressMeter* progress = nullptr;
};

bool requires_complete_history(InspectionOperation operation) noexcept {
    return operation == InspectionOperation::RemoteCommits ||
           operation == InspectionOperation::RemoteSummary ||
           operation == InspectionOperation::RemoteCommit ||
           operation == InspectionOperation::RemoteContents ||
           operation == InspectionOperation::RemoteContentsAudit ||
           operation == InspectionOperation::RemoteContent ||
           operation == InspectionOperation::RemoteLog;
}

InspectionError error(InspectionOperation operation,
                      InspectionErrorCode code,
                      std::string detail,
                      std::vector<std::string> candidate_ids = {}) {
    return InspectionError{.operation = operation,
                           .code = code,
                           .detail = std::move(detail),
                           .candidate_ids = std::move(candidate_ids)};
}

std::unexpected<InspectionError>
fail(InspectionOperation operation,
     InspectionErrorCode code,
     std::string detail,
     std::vector<std::string> candidate_ids = {}) {
    return std::unexpected(
        error(operation, code, std::move(detail), std::move(candidate_ids)));
}

std::unexpected<InspectionError> obs_fail(InspectionOperation operation,
                                          std::string detail) {
    return fail(operation,
                InspectionErrorCode::RemoteObservationFailure,
                std::move(detail));
}

std::unexpected<InspectionError> dest_fail(InspectionOperation operation,
                                           std::string detail) {
    return fail(
        operation, InspectionErrorCode::DestinationFailure, std::move(detail));
}

template <typename PayloadT>
InspectionResponse make_response(InspectionOperation operation,
                                 PayloadT&& payload) {
    return InspectionResponse{.operation = operation,
                              .payload = std::forward<PayloadT>(payload)};
}

template <typename PayloadT>
std::expected<InspectionResponse, InspectionError>
make_response(InspectionOperation operation,
              std::expected<PayloadT, InspectionError> payload) {
    if (!payload) {
        return std::unexpected(payload.error());
    }
    return make_response(operation, std::move(*payload));
}

InspectionError map_runtime_error(InspectionOperation operation,
                                  const runtime::Error& source) {
    return error(
        operation,
        detail::map_runtime_error_code(source.code,
                                       InspectionErrorCode::InvalidProfile,
                                       InspectionErrorCode::ProfileNotFound,
                                       InspectionErrorCode::RuntimeFailure,
                                       InspectionErrorCode::RuntimeFailure,
                                       InspectionErrorCode::RuntimeFailure),
        source.detail);
}

std::expected<void, InspectionError>
resolve_key(const Credentials& credentials,
            const runtime::RuntimeData& runtime_data,
            runtime::vault::KeyBytes& output,
            InspectionOperation operation) {
    return detail::resolve_vault_key<InspectionError>(
        credentials,
        runtime_data,
        output,
        detail::VaultKeyPolicy<InspectionError>{
            .read_only = true,
            .missing_code = InspectionErrorCode::CredentialsRequired,
            .mismatch_code = InspectionErrorCode::CredentialFailure,
            .io_code = InspectionErrorCode::RuntimeFailure,
            .credential_code = InspectionErrorCode::CredentialFailure,
            .missing_detail =
                "credentials are required to inspect remote history",
        },
        [&](InspectionErrorCode code, std::string msg) {
            return error(operation, code, std::move(msg));
        });
}

observation::history::ObservationHints
make_observation_hints(const runtime::RuntimeData& runtime_data,
                       InspectionOperation operation,
                       const history_storage::RemoteLayout& layout) {
    observation::history::ObservationHints hints;
    auto persisted = state_storage::load_state(runtime_data.database_path);
    if (!persisted || !*persisted) {
        return hints;
    }

    const bool use_frontier = operation == InspectionOperation::RemoteTree ||
                              operation == InspectionOperation::RemoteStat ||
                              operation == InspectionOperation::RemoteGet ||
                              operation == InspectionOperation::RemoteRestore;
    return observation::history::make_observation_hints(
        std::move(**persisted), layout, use_frontier);
}

using ObservedCommitIndex =
    std::unordered_map<std::string_view, const kasumi::history::LoadedCommit*>;

std::expected<ObservedCommitIndex, InspectionError> index_observed_commits(
    const std::vector<kasumi::history::LoadedCommit>& commits,
    InspectionOperation operation) {
    ObservedCommitIndex result;
    result.reserve(commits.size());
    for (const auto& commit : commits) {
        if (!result.emplace(commit.id, &commit).second) {
            return obs_fail(operation,
                            "remote history contains duplicate commit");
        }
    }
    return result;
}

bool valid_commit_snapshot(const kasumi::history::LoadedCommit& loaded) {
    return !loaded.commit.tree.rows.empty() &&
           kasumi::valid_snapshot(loaded.commit.tree, false);
}

bool higher_head_first(std::uint64_t left_height,
                       std::string_view left_id,
                       std::uint64_t right_height,
                       std::string_view right_id) noexcept {
    return left_height != right_height ? left_height > right_height
                                       : left_id < right_id;
}

void count_tree_entries(const Snapshot& tree,
                        std::uint64_t& directories,
                        std::uint64_t& files) noexcept {
    for (std::size_t index = 1; index < tree.rows.size(); ++index) {
        ++(tree.rows[index].is_directory ? directories : files);
    }
}

std::string
encode_machine_id_hex(std::span<const std::uint8_t, 16> machine_id) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(32U);
    for (const auto byte : machine_id) {
        out.push_back(kHex[(byte >> 4U) & 0x0FU]);
        out.push_back(kHex[byte & 0x0FU]);
    }
    return out;
}

std::optional<RemoteCommitAuthorship>
make_remote_authorship(const kasumi::history::CommitAuthorship& authorship) {
    if (!kasumi::history::has_commit_authorship(authorship)) {
        return std::nullopt;
    }
    RemoteCommitOrigin origin = RemoteCommitOrigin::Unknown;
    switch (authorship.operation) {
        case kasumi::history::CommitOriginOperation::Unknown:
            origin = RemoteCommitOrigin::Unknown;
            break;
        case kasumi::history::CommitOriginOperation::Sync:
            origin = RemoteCommitOrigin::Sync;
            break;
        case kasumi::history::CommitOriginOperation::Repack:
            origin = RemoteCommitOrigin::Repack;
            break;
        case kasumi::history::CommitOriginOperation::ResolveMissing:
            origin = RemoteCommitOrigin::ResolveMissing;
            break;
    }
    return RemoteCommitAuthorship{
        .operation = origin,
        .machine_id_hex = encode_machine_id_hex(authorship.machine_id),
        .machine_name = authorship.machine_name,
    };
}

std::expected<RemoteHeadInfo, InspectionError>
make_head_info(std::string_view id,
               const ObservedCommitIndex& commits,
               InspectionOperation operation) {
    const auto observed = commits.find(id);
    if (observed == commits.end() ||
        !valid_commit_snapshot(*observed->second)) {
        return obs_fail(operation,
                        "logical head does not have a valid observed commit");
    }
    const auto* match = observed->second;
    const auto& tree = match->commit.tree;
    RemoteHeadInfo result{.commit_id = match->id,
                          .height = match->commit.height,
                          .created_at = match->commit.created_at,
                          .parent_ids = match->commit.parents,
                          .root_hash = hash_hex(tree.rows.front().hash),
                          .total_bytes = tree.rows.front().size,
                          .authorship =
                              make_remote_authorship(match->commit.authorship)};
    count_tree_entries(tree, result.directory_count, result.file_count);
    return result;
}

std::expected<std::vector<RemoteHeadInfo>, InspectionError>
make_head_infos(const observation::history::StorageView& observed,
                InspectionOperation operation) {
    auto commits =
        index_observed_commits(observed.reachable_commits, operation);
    if (!commits) {
        return std::unexpected(commits.error());
    }
    std::vector<RemoteHeadInfo> result;
    result.reserve(observed.logical_heads.size());
    for (const auto& id : observed.logical_heads) {
        auto head = make_head_info(id, *commits, operation);
        if (!head) {
            return std::unexpected(head.error());
        }
        result.push_back(std::move(*head));
    }
    std::ranges::sort(result, [](const auto& left, const auto& right) {
        return higher_head_first(
            left.height, left.commit_id, right.height, right.commit_id);
    });
    return result;
}

std::vector<std::string> head_ids(const std::vector<RemoteHeadInfo>& heads) {
    std::vector<std::string> result;
    result.reserve(heads.size());
    for (const auto& head : heads) {
        result.push_back(head.commit_id);
    }
    return result;
}

std::expected<RemoteTreeReport, InspectionError>
make_tree_report(const InspectionRequest& request,
                 const observation::history::StorageView& observed,
                 const std::vector<RemoteHeadInfo>& heads,
                 InspectionOperation operation) {
    RemoteTreeReport report{.history_present = observed.history_present};
    if (!observed.history_present) {
        if (request.commit_id)
            return fail(operation,
                        InspectionErrorCode::RemoteCommitNotFound,
                        "commit is not reachable");
        if (request.head_commit_id) {
            return fail(operation,
                        InspectionErrorCode::RemoteHeadNotFound,
                        "requested head is not among current logical heads");
        }
        return report;
    }

    if (heads.empty()) {
        return obs_fail(operation,
                        "remote history has no observed logical head");
    }

    std::string selected_id;
    if (request.commit_id) {
        selected_id = *request.commit_id;
    } else if (request.head_commit_id) {
        const auto selected =
            std::ranges::find(observed.logical_heads, *request.head_commit_id);
        if (selected == observed.logical_heads.end()) {
            return fail(operation,
                        InspectionErrorCode::RemoteHeadNotFound,
                        "requested head is not among current logical heads",
                        head_ids(heads));
        }
        selected_id = *selected;
    } else if (heads.size() > 1) {
        return fail(operation,
                    InspectionErrorCode::HeadSelectionRequired,
                    "Remote history has multiple logical heads.",
                    head_ids(heads));
    } else {
        selected_id = heads.front().commit_id;
    }

    const auto selected = std::ranges::find(
        observed.reachable_commits, selected_id, &history::LoadedCommit::id);
    if (selected == observed.reachable_commits.end() && request.commit_id)
        return fail(operation,
                    InspectionErrorCode::RemoteCommitNotFound,
                    "commit is not reachable");
    if (selected == observed.reachable_commits.end() ||
        !valid_commit_snapshot(*selected)) {
        return obs_fail(operation,
                        "logical head does not have a valid observed commit");
    }

    const auto& tree = selected->commit.tree;
    const auto& root = tree.rows.front();
    report.commit_id = selected->id;
    report.height = selected->commit.height;
    report.created_at = selected->commit.created_at;
    report.root_hash = hash_hex(root.hash);
    report.total_bytes = root.size;
    report.entries.reserve(tree.rows.size() - 1);
    for (std::size_t index = 1; index < tree.rows.size(); ++index) {
        const auto& row = tree.rows[index];
        report.entries.push_back(RemoteTreeEntry{
            .path = row.path,
            .type = row.is_directory ? RemoteTreeEntryType::Directory
                                     : RemoteTreeEntryType::File,
            .logical_hash = hash_hex(row.hash),
            .size = row.size,
        });
    }
    count_tree_entries(tree, report.directory_count, report.file_count);
    return report;
}

RemoteCommitInfo make_commit_info(const kasumi::history::LoadedCommit& loaded,
                                  bool logical_head,
                                  bool physically_marked,
                                  bool ancestral_marked) {
    const auto& rows = loaded.commit.tree.rows;
    return RemoteCommitInfo{
        .commit_id = loaded.id,
        .height = loaded.commit.height,
        .created_at = loaded.commit.created_at,
        .parent_ids = loaded.commit.parents,
        .logical_head = logical_head,
        .physically_marked = physically_marked,
        .ancestral_marked = ancestral_marked,
        .root_hash = hash_hex(rows.front().hash),
        .total_bytes = rows.front().size,
        .entry_count = static_cast<std::uint64_t>(rows.size() - 1),
        .authorship = make_remote_authorship(loaded.commit.authorship),
    };
}

std::expected<RemoteCommitsReport, InspectionError>
make_commits_report(const observation::history::StorageView& observed,
                    InspectionOperation operation) {
    RemoteCommitsReport report{.history_present = observed.history_present,
                               .observed_height = observed.observed_height};
    if (!observed.history_present) {
        return report;
    }
    if (observed.reachable_commits.empty()) {
        return obs_fail(operation,
                        "remote history has no observed reachable commits");
    }

    const std::unordered_set<std::string_view> logical_head_ids(
        observed.logical_heads.begin(), observed.logical_heads.end());
    const std::unordered_set<std::string_view> marked_head_ids(
        observed.marked_heads.begin(), observed.marked_heads.end());
    const std::unordered_set<std::string_view> ancestral_marked_head_ids(
        observed.ancestral_marked_heads.begin(),
        observed.ancestral_marked_heads.end());

    report.commits.reserve(observed.reachable_commits.size());
    std::vector<std::pair<std::uint64_t, std::string>> logical_heads;
    logical_heads.reserve(observed.logical_heads.size());
    for (const auto& loaded : observed.reachable_commits) {
        if (loaded.commit.tree.rows.empty()) {
            return obs_fail(operation,
                            "remote history contains commit without tree");
        }

        const bool logical_head = logical_head_ids.contains(loaded.id);
        if (logical_head) {
            logical_heads.emplace_back(loaded.commit.height, loaded.id);
        }
        report.commits.push_back(
            make_commit_info(loaded,
                             logical_head,
                             marked_head_ids.contains(loaded.id),
                             ancestral_marked_head_ids.contains(loaded.id)));
    }

    if (logical_heads.size() != observed.logical_heads.size()) {
        return obs_fail(operation,
                        "remote resolution references unreachable head");
    }
    std::ranges::sort(logical_heads, [](const auto& left, const auto& right) {
        return higher_head_first(
            left.first, left.second, right.first, right.second);
    });
    report.logical_head_ids.reserve(logical_heads.size());
    for (const auto& logical_head : logical_heads) {
        report.logical_head_ids.push_back(logical_head.second);
    }

    std::ranges::sort(report.commits, [](const auto& left, const auto& right) {
        return std::tie(right.height, right.created_at, left.commit_id) <
               std::tie(left.height, left.created_at, right.commit_id);
    });
    return report;
}

bool valid_logical_path(std::string_view path) {
    return path == "/" || kasumi::valid_logical_path(path);
}

struct CommitInspectionTarget {
    const Snapshot* tree = nullptr;
    const kasumi::history::StorageManifest* manifest = nullptr;
    std::uint64_t observed_height = 0;
    bool has_conflicts = false;
    std::optional<std::string> commit_id;
};

std::expected<CommitInspectionTarget, InspectionError>
resolve_commit_target(const InspectionRequest& request,
                      const observation::history::StorageView& observed,
                      InspectionOperation operation) {
    if (!request.commit_id) {
        return CommitInspectionTarget{
            .tree = &observed.effective_tree,
            .manifest = &observed.storage_manifest,
            .observed_height = observed.observed_height,
            .has_conflicts = observed.has_conflicts,
            .commit_id = std::nullopt,
        };
    }
    const auto selected = std::ranges::find(observed.reachable_commits,
                                            *request.commit_id,
                                            &kasumi::history::LoadedCommit::id);
    if (selected == observed.reachable_commits.end()) {
        return fail(operation,
                    InspectionErrorCode::RemoteCommitNotFound,
                    "commit is not reachable in current remote history");
    }
    if (!valid_commit_snapshot(*selected)) {
        return obs_fail(operation, "remote commit does not have a valid tree");
    }
    return CommitInspectionTarget{
        .tree = &selected->commit.tree,
        .manifest = &selected->commit.storage,
        .observed_height = selected->commit.height,
        .has_conflicts = false,
        .commit_id = selected->id,
    };
}

std::expected<RemoteStatReport, InspectionError>
make_stat_report(const InspectionRequest& request,
                 const observation::history::StorageView& observed,
                 InspectionOperation operation) {
    auto target = resolve_commit_target(request, observed, operation);
    if (!target) {
        return std::unexpected(target.error());
    }
    const auto requested = request.logical_path.value_or("");
    const auto canonical = requested == "/" ? std::string_view{} : requested;
    const bool tree_available =
        observed.history_present && target->tree != nullptr;
    const auto* row =
        tree_available ? find_row(*target->tree, canonical) : nullptr;
    if (row == nullptr) {
        return fail(operation,
                    InspectionErrorCode::RemotePathNotFound,
                    target->commit_id
                        ? "path does not exist in requested remote commit"
                        : "path does not exist in remote logical tree");
    }
    RemoteStatReport report{
        .observed_height = target->observed_height,
        .has_conflicts = target->has_conflicts,
        .commit_id = target->commit_id,
        .path = row->path.empty() ? "/" : row->path,
        .type = row->is_directory ? RemoteTreeEntryType::Directory
                                  : RemoteTreeEntryType::File,
        .logical_hash = hash_hex(row->hash),
        .size = row->size,
        .modified_at_unix_nanoseconds = row->mtime,
    };
    if (target->manifest && !row->is_directory) {
        if (auto* packed =
                history::find_packed_blob(*target->manifest, row->hash))
            report.pack_hash = hash_hex(packed->pack_hash);
        if (auto* layout =
                history::find_chunked_file(*target->manifest, row->hash)) {
            for (const auto& chunk : layout->chunks)
                report.chunks.push_back({hash_hex(chunk.hash), chunk.size});
        }
    }
    return report;
}

std::expected<std::filesystem::path, InspectionError>
resolve_destination_path(const std::filesystem::path& raw_destination,
                         InspectionOperation operation) {
    if (raw_destination.empty()) {
        return fail(operation,
                    InspectionErrorCode::InvalidRequest,
                    "requested destination is invalid");
    }
    std::error_code filesystem_error;
    auto destination =
        std::filesystem::absolute(raw_destination, filesystem_error)
            .lexically_normal();
    if (filesystem_error || destination.filename().empty()) {
        return dest_fail(operation, "failed to resolve destination");
    }
    const auto parent = destination.parent_path();
    const auto parent_status =
        std::filesystem::symlink_status(parent, filesystem_error);
    if (filesystem_error || std::filesystem::is_symlink(parent_status) ||
        platform::private_storage::is_reparse_or_symlink(parent) ||
        !std::filesystem::is_directory(parent_status)) {
        return dest_fail(
            operation,
            "destination parent directory does not exist or is not safe");
    }
    const auto destination_status =
        std::filesystem::symlink_status(destination, filesystem_error);
    if (filesystem_error == std::errc::no_such_file_or_directory) {
        filesystem_error.clear();
    } else if (filesystem_error ||
               std::filesystem::is_symlink(destination_status) ||
               platform::private_storage::is_reparse_or_symlink(destination) ||
               std::filesystem::is_directory(destination_status) ||
               (!std::filesystem::is_regular_file(destination_status) &&
                destination_status.type() !=
                    std::filesystem::file_type::not_found)) {
        return dest_fail(operation, "destination is not a safe regular file");
    }
    return destination;
}

std::expected<std::filesystem::path, InspectionError>
resolve_destination(const InspectionRequest& request,
                    InspectionOperation operation) {
    const auto requested = request.destination_path.value_or("");
    if (requested.empty()) {
        return fail(operation,
                    InspectionErrorCode::InvalidRequest,
                    "requested destination is invalid");
    }
    return resolve_destination_path(platform::path::from_utf8(requested),
                                    operation);
}

template <typename Writer>
std::expected<void, InspectionError> write_and_publish_private_file(
    const std::filesystem::path& destination,
    InspectionOperation operation,
    Writer&& writer) {
    auto token = platform::random::hex_id();
    if (!token) {
        return dest_fail(operation, "failed to prepare destination");
    }
    const auto temporary =
        destination.parent_path() / (".kasumi-download-" + *token + ".tmp");
    auto private_tmp =
        platform::private_storage::create_private_file(temporary);
    if (!private_tmp) {
        return dest_fail(operation, "failed to prepare destination file");
    }
    const auto cleanup = [&] {
        static_cast<void>(
            platform::private_storage::remove_private_file_if_owned(
                *private_tmp));
    };
    if (auto wrote = writer(*private_tmp); !wrote) {
        cleanup();
        return wrote;
    }
    if (!platform::private_storage::publish_private_file(*private_tmp,
                                                         destination)) {
        cleanup();
        return dest_fail(operation, "failed to install download");
    }
    return {};
}

std::expected<void, InspectionError> install_remote_file(
    const std::filesystem::path& plaintext,
    const std::filesystem::path& destination,
    InspectionOperation operation,
    std::optional<platform::private_storage::FileSlice> slice = std::nullopt) {
    return write_and_publish_private_file(
        destination,
        operation,
        [&](platform::private_storage::PrivateOutputFile& private_tmp)
            -> std::expected<void, InspectionError> {
            std::array<std::uint8_t, 65536> buffer{};
            std::expected<void, InspectionError> write_error;
            const auto streamed = platform::private_storage::stream_regular_file(
                plaintext,
                buffer,
                [&](std::span<const std::uint8_t> chunk) {
                    if (!platform::private_storage::write_private_file(
                            private_tmp, chunk.data(), chunk.size())) {
                        write_error = dest_fail(
                            operation, "failed to prepare destination file");
                        return false;
                    }
                    return true;
                },
                std::nullopt,
                slice);
            if (!write_error) {
                return write_error;
            }
            if (!streamed) {
                return dest_fail(operation, "failed to read downloaded file");
            }
            return {};
        });
}

std::expected<void, InspectionError> install_remote_bytes(
    std::span<const std::uint8_t> bytes,
    const std::filesystem::path& destination,
    InspectionOperation operation,
    std::optional<platform::private_storage::FileSlice> slice = std::nullopt) {
    if (slice) {
        if (slice->offset > bytes.size() ||
            slice->size > bytes.size() - slice->offset) {
            return fail(operation,
                        InspectionErrorCode::InvalidRequest,
                        "invalid byte range");
        }
        bytes = bytes.subspan(slice->offset, slice->size);
    }
    return write_and_publish_private_file(
        destination,
        operation,
        [&](platform::private_storage::PrivateOutputFile& private_tmp)
            -> std::expected<void, InspectionError> {
            if (!bytes.empty() &&
                !platform::private_storage::write_private_file(
                    private_tmp, bytes.data(), bytes.size())) {
                return dest_fail(operation,
                                 "failed to prepare destination file");
            }
            return {};
        });
}

struct RemoteDownloadTarget {
    Hash file_hash{};
    std::uint64_t file_size = 0;
    std::string logical_hash;
    std::string content_id;
    std::string path;
    std::optional<std::string> commit_id;
    std::optional<Hash> pack_hash;
    std::vector<history::ChunkSlice> chunks;
    std::optional<std::filesystem::path> cached_plaintext;
};

RemoteDownloadTarget make_download_target(
    const NodeRow& row,
    const history::StorageManifest& manifest,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    std::optional<std::string> commit_id) {
    RemoteDownloadTarget target{
        .file_hash = row.hash,
        .file_size = row.size,
        .logical_hash = hash_hex(row.hash),
        .path = row.path,
        .commit_id = std::move(commit_id),
    };
    if (const auto* packed = history::find_packed_blob(manifest, row.hash)) {
        target.pack_hash = packed->pack_hash;
        target.content_id = crypto::pack_identifier(key, packed->pack_hash);
    } else if (const auto* chunked =
                   history::find_chunked_file(manifest, row.hash)) {
        target.content_id = crypto::content_identifier(key, row.hash);
        target.chunks = chunked->chunks;
    } else {
        target.content_id = crypto::content_identifier(key, row.hash);
    }
    return target;
}

std::expected<RemoteFileReport, InspectionError> download_target_to_destination(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace_root,
    ProgressMeter* progress,
    InspectionOperation operation,
    RemoteDownloadTarget& target,
    const std::filesystem::path& destination,
    const std::optional<DownloadSlice>& requested_slice,
    std::unordered_map<std::string, std::filesystem::path>* verified_chunks =
        nullptr,
    std::deque<std::string>* verified_chunk_order = nullptr,
    bool allow_cache_plaintext = false) {
    using platform::private_storage::FileSlice;
    std::optional<FileSlice> slice;
    if (requested_slice) {
        const auto [offset, length] = *requested_slice;
        if (!length || offset >= target.file_size ||
            length > target.file_size - offset)
            return fail(operation,
                        InspectionErrorCode::InvalidRequest,
                        "invalid byte range");
        slice = FileSlice{offset, length};
    }

    if (target.cached_plaintext) {
        std::error_code ec;
        const auto st =
            std::filesystem::symlink_status(*target.cached_plaintext, ec);
        if (!ec && std::filesystem::is_regular_file(st) &&
            !std::filesystem::is_symlink(st) &&
            !platform::private_storage::is_reparse_or_symlink(
                *target.cached_plaintext)) {
            if (progress) {
                begin_progress_phase(*progress, Activity::Installing, 1);
            }
            if (auto installed = install_remote_file(
                    *target.cached_plaintext, destination, operation, slice);
                !installed) {
                return std::unexpected(installed.error());
            }
            if (progress) {
                progress_add(progress->work);
            }
            return RemoteFileReport{.commit_id = target.commit_id,
                                    .path = target.path,
                                    .destination_path =
                                        platform::path::to_utf8(destination),
                                    .logical_hash = target.logical_hash,
                                    .content_id = target.content_id,
                                    .size = target.file_size};
        }
        target.cached_plaintext.reset();
    }

    if (progress) {
        begin_progress_phase(*progress,
                             Activity::Downloading,
                             target.chunks.empty() ? 1 : target.chunks.size());
    }
    const auto plaintext = workspace_root / "remote-content.plain";

    if (target.pack_hash) {
        const auto encrypted = workspace_root / "remote-pack.enc";
        auto downloaded =
            transport::get(storage, target.content_id, encrypted);
        if (!downloaded) {
            const bool not_found =
                downloaded.error().code == transport::ErrorCode::ObjectNotFound;
            return fail(operation,
                        not_found
                            ? InspectionErrorCode::RemoteContentNotFound
                            : InspectionErrorCode::RemoteObservationFailure,
                        not_found ? "remote file content not found"
                                  : "failed to download remote content");
        }
        if (progress) {
            begin_progress_phase(*progress, Activity::Verifying, 1);
        }
        auto verified =
            crypto::pack::load_verified_pack(encrypted, key, *target.pack_hash);
        std::error_code rm_ec;
        std::filesystem::remove(encrypted, rm_ec);
        if (!verified) {
            return fail(operation,
                        InspectionErrorCode::RemoteContentInvalid,
                        "remote pack failed cryptographic authentication");
        }
        const auto member =
            crypto::pack::find_verified_pack_member(*verified, target.file_hash);
        if (!member || member->size() != target.file_size) {
            return fail(operation,
                        InspectionErrorCode::RemoteContentInvalid,
                        "extracted member failed cryptographic authentication");
        }
        if (progress) {
            progress_add(progress->work);
            begin_progress_phase(*progress, Activity::Installing, 1);
        }
        if (allow_cache_plaintext) {
            const auto cached = workspace_root / "remote-member.plain";
            if (auto cached_ok =
                    install_remote_bytes(*member, cached, operation);
                !cached_ok) {
                return std::unexpected(cached_ok.error());
            }
            target.cached_plaintext = cached;
        }
        if (auto installed =
                install_remote_bytes(*member, destination, operation, slice);
            !installed) {
            return std::unexpected(installed.error());
        }
        if (progress) {
            progress_add(progress->work);
        }
        return RemoteFileReport{.commit_id = target.commit_id,
                                .path = target.path,
                                .destination_path =
                                    platform::path::to_utf8(destination),
                                .logical_hash = target.logical_hash,
                                .content_id = target.content_id,
                                .size = target.file_size};
    } else if (!target.chunks.empty()) {
        const auto enc = workspace_root / "remote-chunk.enc";
        std::error_code rm_ec;
        std::filesystem::remove(plaintext, rm_ec);
        auto private_out =
            platform::private_storage::create_private_file(plaintext);
        if (!private_out) {
            return dest_fail(operation,
                             "failed to open temporary download file");
        }
        std::vector<std::uint8_t> copy_buf(256U * 1024U);
        crypto::secure_memory::WipeGuard copy_buf_guard{copy_buf};
        std::uint64_t position = 0;
        for (const auto& chunk : target.chunks) {
            if (platform::cancellation::requested()) {
                static_cast<void>(
                    platform::private_storage::remove_private_file_if_owned(
                        *private_out));
                return obs_fail(operation, "download cancelled by user");
            }
            const auto begin = position;
            position += chunk.size;
            std::optional<FileSlice> part;
            if (slice) {
                const auto from = std::max(begin, slice->offset);
                const auto until =
                    std::min(position, slice->offset + slice->size);
                if (from >= until)
                    continue;
                part = FileSlice{from - begin, until - from};
            }
            const auto chex = hash_hex(chunk.hash);
            std::filesystem::path chunk_plain;
            bool cached_hit = false;
            if (verified_chunks != nullptr) {
                if (const auto it = verified_chunks->find(chex);
                    it != verified_chunks->end()) {
                    std::error_code st_ec;
                    const auto st =
                        std::filesystem::symlink_status(it->second, st_ec);
                    if (!st_ec && std::filesystem::is_regular_file(st) &&
                        !std::filesystem::is_symlink(st) &&
                        !platform::private_storage::is_reparse_or_symlink(
                            it->second)) {
                        chunk_plain = it->second;
                        cached_hit = true;
                    } else {
                        verified_chunks->erase(it);
                        if (verified_chunk_order != nullptr) {
                            std::erase(*verified_chunk_order, chex);
                        }
                    }
                }
            }
            if (!cached_hit) {
                const auto cid =
                    crypto::content_identifier(key, chunk.hash);
                chunk_plain =
                    verified_chunks != nullptr
                        ? (workspace_root / ("chunk-" + chex + ".plain"))
                        : (workspace_root / "remote-chunk.plain");
                auto downloaded = transport::get(storage, cid, enc);
                if (!downloaded) {
                    std::filesystem::remove(enc, rm_ec);
                    static_cast<void>(
                        platform::private_storage::remove_private_file_if_owned(
                            *private_out));
                    const bool not_found =
                        downloaded.error().code ==
                        transport::ErrorCode::ObjectNotFound;
                    return fail(
                        operation,
                        not_found
                            ? InspectionErrorCode::RemoteContentNotFound
                            : InspectionErrorCode::RemoteObservationFailure,
                        not_found ? "remote file chunk not found"
                                  : "failed to download remote chunk");
                }
                const bool decrypted =
                    crypto::decrypt_file(enc, chunk_plain, key) &&
                    crypto::content::verify_file(chunk_plain, chex, chunk.size);
                std::filesystem::remove(enc, rm_ec);
                if (!decrypted) {
                    std::filesystem::remove(chunk_plain, rm_ec);
                    static_cast<void>(
                        platform::private_storage::remove_private_file_if_owned(
                            *private_out));
                    return fail(
                        operation,
                        InspectionErrorCode::RemoteContentInvalid,
                        "remote chunk failed cryptographic authentication");
                }
                if (verified_chunks != nullptr) {
                    constexpr std::size_t kMaxCachedChunks = 2U;
                    if (verified_chunk_order != nullptr) {
                        while (verified_chunks->size() >= kMaxCachedChunks &&
                               !verified_chunk_order->empty()) {
                            const auto victim_hex =
                                std::move(verified_chunk_order->front());
                            verified_chunk_order->pop_front();
                            if (const auto vit =
                                    verified_chunks->find(victim_hex);
                                vit != verified_chunks->end()) {
                                std::filesystem::remove(vit->second, rm_ec);
                                verified_chunks->erase(vit);
                            }
                        }
                        verified_chunk_order->push_back(chex);
                    }
                    verified_chunks->insert_or_assign(chex, chunk_plain);
                }
            }
            bool write_failed = false;
            auto streamed = platform::private_storage::stream_regular_file(
                chunk_plain,
                copy_buf,
                [&](std::span<const std::uint8_t> slab) {
                    if (!slab.empty() &&
                        !platform::private_storage::write_private_file(
                            *private_out, slab.data(), slab.size())) {
                        write_failed = true;
                        return false;
                    }
                    return true;
                },
                chunk.size,
                part);
            if (!streamed || write_failed) {
                static_cast<void>(
                    platform::private_storage::remove_private_file_if_owned(
                        *private_out));
                return dest_fail(operation, "failed to assemble remote chunks");
            }
        }
        platform::private_storage::close_private_file(*private_out);
        if (progress) {
            begin_progress_phase(*progress, Activity::Verifying, 1);
        }
        if (!slice && !crypto::content::verify_file(
                         plaintext, target.logical_hash, target.file_size)) {
            return fail(operation,
                        InspectionErrorCode::RemoteContentInvalid,
                        "assembled remote content failed verification");
        }
        // The assembly already contains only the authenticated chunk slices.
        slice.reset();
    } else {
        const auto encrypted = workspace_root / "remote-content.enc";
        std::error_code rm_ec;
        auto downloaded =
            transport::get(storage, target.content_id, encrypted);
        if (!downloaded) {
            std::filesystem::remove(encrypted, rm_ec);
            const bool not_found =
                downloaded.error().code == transport::ErrorCode::ObjectNotFound;
            return fail(operation,
                        not_found
                            ? InspectionErrorCode::RemoteContentNotFound
                            : InspectionErrorCode::RemoteObservationFailure,
                        not_found ? "remote file content not found"
                                  : "failed to download remote content");
        }
        if (progress) {
            begin_progress_phase(*progress, Activity::Verifying, 1);
        }
        const bool verified =
            crypto::decrypt_file(encrypted, plaintext, key) &&
            crypto::content::verify_file(
                plaintext, target.logical_hash, target.file_size);
        std::filesystem::remove(encrypted, rm_ec);
        if (!verified) {
            std::filesystem::remove(plaintext, rm_ec);
            return fail(operation,
                        InspectionErrorCode::RemoteContentInvalid,
                        "remote content failed cryptographic authentication");
        }
        if (allow_cache_plaintext) {
            target.cached_plaintext = plaintext;
        }
    }
    if (progress) {
        progress_add(progress->work);
        begin_progress_phase(*progress, Activity::Installing, 1);
    }
    if (auto installed =
            install_remote_file(plaintext, destination, operation, slice);
        !installed) {
        return std::unexpected(installed.error());
    }
    if (progress) {
        progress_add(progress->work);
    }
    return RemoteFileReport{.commit_id = target.commit_id,
                            .path = target.path,
                            .destination_path =
                                platform::path::to_utf8(destination),
                            .logical_hash = target.logical_hash,
                            .content_id = target.content_id,
                            .size = target.file_size};
}

struct ResolvedRemoteFile {
    CommitInspectionTarget commit;
    const NodeRow* row = nullptr;
};

std::expected<ResolvedRemoteFile, InspectionError>
resolve_remote_file_target(const InspectionRequest& request,
                           const observation::history::StorageView& observed,
                           InspectionOperation operation,
                           std::string_view logical_path) {
    auto target = resolve_commit_target(request, observed, operation);
    if (!target) {
        return std::unexpected(target.error());
    }
    const bool tree_available = observed.history_present &&
                                target->tree != nullptr &&
                                target->manifest != nullptr;
    const auto* row =
        tree_available ? find_row(*target->tree, logical_path) : nullptr;
    if (row == nullptr) {
        return fail(operation,
                    InspectionErrorCode::RemotePathNotFound,
                    target->commit_id
                        ? "path does not exist in requested remote commit"
                        : "path does not exist in remote logical tree");
    }
    if (row->is_directory) {
        return fail(operation,
                    InspectionErrorCode::RemotePathIsDirectory,
                    "remote path is a directory");
    }
    return ResolvedRemoteFile{std::move(*target), row};
}

std::expected<RemoteFileReport, InspectionError>
download_remote_file(const InspectionRequest& request,
                     const observation::history::StorageView& observed,
                     InspectionContext& context,
                     InspectionOperation operation) {
    auto resolved = resolve_remote_file_target(
        request, observed, operation, request.logical_path.value_or(""));
    if (!resolved) {
        return std::unexpected(resolved.error());
    }
    auto destination = resolve_destination(request, operation);
    if (!destination) {
        return std::unexpected(destination.error());
    }
    auto dl_target = make_download_target(*resolved->row,
                                          *resolved->commit.manifest,
                                          context.key,
                                          resolved->commit.commit_id);
    return download_target_to_destination(context.storage,
                                          context.key,
                                          context.workspace->root,
                                          context.progress,
                                          operation,
                                          dl_target,
                                          *destination,
                                          request.download_slice);
}

bool same_node_version(const NodeRow* left, const NodeRow* right) noexcept {
    if (left == nullptr || right == nullptr) {
        return left == right;
    }
    if (left->is_directory != right->is_directory) {
        return false;
    }
    if (left->is_directory) {
        return true;
    }
    return left->hash == right->hash && left->size == right->size;
}

std::expected<RemoteLogReport, InspectionError>
make_log_report(const InspectionRequest& request,
                const observation::history::StorageView& observed,
                InspectionOperation operation) {
    const auto path = request.logical_path.value_or("");
    if (!observed.history_present) {
        return fail(operation,
                    InspectionErrorCode::RemotePathNotFound,
                    "path was not found in reachable remote history");
    }

    auto commits =
        index_observed_commits(observed.reachable_commits, operation);
    if (!commits) {
        return std::unexpected(commits.error());
    }
    const std::unordered_set<std::string_view> logical_head_ids(
        observed.logical_heads.begin(), observed.logical_heads.end());

    RemoteLogReport report{
        .path = path,
        .observed_height = observed.observed_height,
        .present_in_current_tree =
            find_row(observed.effective_tree, path) != nullptr,
    };

    for (const auto& loaded : observed.reachable_commits) {
        if (!valid_commit_snapshot(loaded)) {
            return obs_fail(operation,
                            "remote commit does not have a valid tree");
        }
        const auto* curr = find_row(loaded.commit.tree, path);
        std::optional<RemotePathChangeKind> change;
        if (loaded.commit.parents.empty()) {
            if (curr != nullptr) {
                change = RemotePathChangeKind::Added;
            }
        } else {
            std::vector<const NodeRow*> parent_nodes;
            std::size_t missing_parents = 0;
            for (const auto& parent_id : loaded.commit.parents) {
                const auto it = commits->find(parent_id);
                if (it == commits->end()) {
                    ++missing_parents;
                } else {
                    parent_nodes.push_back(
                        find_row(it->second->commit.tree, path));
                }
            }
            if (parent_nodes.empty()) {
                if (curr != nullptr) {
                    change = RemotePathChangeKind::Observed;
                }
            } else if (missing_parents == 0 &&
                       std::ranges::all_of(
                           parent_nodes, [&](const NodeRow* parent_row) {
                               return same_node_version(parent_row, curr);
                           })) {
                change = std::nullopt;
            } else if (curr == nullptr) {
                if (std::ranges::any_of(parent_nodes,
                                        [](const NodeRow* parent_row) {
                                            return parent_row != nullptr;
                                        })) {
                    change = RemotePathChangeKind::Deleted;
                }
            } else if (missing_parents == 0 &&
                       std::ranges::all_of(parent_nodes,
                                           [](const NodeRow* parent_row) {
                                               return parent_row == nullptr;
                                           })) {
                change = RemotePathChangeKind::Added;
            } else if (std::ranges::any_of(
                           parent_nodes, [&](const NodeRow* parent_row) {
                               return !same_node_version(parent_row, curr);
                           })) {
                change = RemotePathChangeKind::Modified;
            } else {
                change = RemotePathChangeKind::Observed;
            }
        }

        if (!change.has_value()) {
            continue;
        }
        report.entries.push_back(RemoteLogEntry{
            .commit_id = loaded.id,
            .height = loaded.commit.height,
            .created_at = loaded.commit.created_at,
            .logical_head = logical_head_ids.contains(loaded.id),
            .change = *change,
            .type =
                curr == nullptr
                    ? std::nullopt
                    : std::optional<
                          RemoteTreeEntryType>{curr->is_directory
                                                   ? RemoteTreeEntryType::
                                                         Directory
                                                   : RemoteTreeEntryType::File},
            .logical_hash = (curr == nullptr || curr->is_directory)
                                ? std::string{}
                                : hash_hex(curr->hash),
            .size = curr == nullptr ? 0ULL : curr->size,
            .modified_at_unix_nanoseconds = curr == nullptr ? 0LL : curr->mtime,
            .authorship = make_remote_authorship(loaded.commit.authorship),
        });
    }

    if (report.entries.empty() && !report.present_in_current_tree) {
        return fail(operation,
                    InspectionErrorCode::RemotePathNotFound,
                    "path was not found in reachable remote history");
    }

    std::ranges::sort(report.entries, [](const auto& left, const auto& right) {
        return std::tie(right.height, right.created_at, left.commit_id) <
               std::tie(left.height, left.created_at, right.commit_id);
    });
    return report;
}

bool path_components_equal(const std::filesystem::path& left,
                           const std::filesystem::path& right) noexcept {
#if defined(_WIN32)
    const auto l = left.wstring();
    const auto r = right.wstring();
    return CompareStringOrdinal(l.c_str(), -1, r.c_str(), -1, TRUE) ==
           CSTR_EQUAL;
#else
    return left == right;
#endif
}

bool is_path_prefix(const std::filesystem::path& prefix,
                    const std::filesystem::path& target) {
    auto target_it = target.begin();
    for (auto prefix_it = prefix.begin(); prefix_it != prefix.end();
         ++prefix_it, ++target_it) {
        if (target_it == target.end() ||
            !path_components_equal(*prefix_it, *target_it)) {
            return false;
        }
    }
    return true;
}

bool paths_overlap(const std::filesystem::path& left,
                   const std::filesystem::path& right) {
    std::error_code ec;
    const auto norm_left = std::filesystem::weakly_canonical(
        std::filesystem::absolute(left, ec), ec);
    if (ec) {
        return true;
    }
    const auto norm_right = std::filesystem::weakly_canonical(
        std::filesystem::absolute(right, ec), ec);
    if (ec) {
        return true;
    }
    return is_path_prefix(norm_left, norm_right) ||
           is_path_prefix(norm_right, norm_left);
}

std::expected<std::filesystem::path, InspectionError>
resolve_restore_destination(const InspectionRequest& request,
                            const std::filesystem::path& local_dir,
                            InspectionOperation operation) {
    const auto requested = request.destination_path.value_or("");
    if (requested.empty()) {
        return fail(operation,
                    InspectionErrorCode::InvalidRequest,
                    "requested destination is invalid");
    }
    std::error_code ec;
    auto destination =
        std::filesystem::absolute(platform::path::from_utf8(requested), ec)
            .lexically_normal();
    if (ec || destination.empty()) {
        return dest_fail(operation, "failed to resolve restore destination");
    }
    if (!destination.has_filename() && destination != destination.root_path()) {
        destination = destination.parent_path();
    }
    if (destination.empty() || destination == destination.root_path() ||
        !destination.has_filename()) {
        return dest_fail(operation, "restore destination cannot be root path");
    }
    if (paths_overlap(destination, local_dir)) {
        return dest_fail(
            operation,
            "restore destination cannot overlap the profile synchronized "
            "directory");
    }

    const auto dst_status = std::filesystem::symlink_status(destination, ec);
    if (ec == std::errc::no_such_file_or_directory) {
        ec.clear();
        const auto parent = destination.parent_path();
        const auto parent_status = std::filesystem::symlink_status(parent, ec);
        if (ec || std::filesystem::is_symlink(parent_status) ||
            platform::private_storage::is_reparse_or_symlink(parent) ||
            !std::filesystem::is_directory(parent_status)) {
            return dest_fail(
                operation,
                "restore destination parent directory does not exist or is "
                "not safe");
        }
        return destination;
    }
    if (ec || std::filesystem::is_symlink(dst_status) ||
        platform::private_storage::is_reparse_or_symlink(destination) ||
        !std::filesystem::is_directory(dst_status)) {
        return dest_fail(operation,
                         "restore destination is not a safe empty directory");
    }
    std::filesystem::directory_iterator dir_it(destination, ec);
    if (ec || dir_it != std::filesystem::directory_iterator{}) {
        return dest_fail(operation,
                         "restore destination directory must be empty");
    }
    return destination;
}

std::expected<RemoteRestoreReport, InspectionError>
restore_remote_tree(const InspectionRequest& request,
                    const observation::history::StorageView& observed,
                    InspectionContext& context,
                    InspectionOperation operation) {
    auto target = resolve_commit_target(request, observed, operation);
    if (!target) {
        return std::unexpected(target.error());
    }

    const auto requested = request.logical_path.value_or("");
    const std::string canonical_prefix =
        (requested.empty() || requested == "/") ? std::string{} : requested;
    const bool tree_available = observed.history_present &&
                                target->tree != nullptr &&
                                target->manifest != nullptr;
    const auto* root_row =
        tree_available ? find_row(*target->tree, canonical_prefix) : nullptr;
    if (root_row == nullptr) {
        return fail(operation,
                    InspectionErrorCode::RemotePathNotFound,
                    target->commit_id
                        ? "path does not exist in requested remote commit"
                        : "path does not exist in remote logical tree");
    }

    auto destination = resolve_restore_destination(
        request, context.runtime.local_dir, operation);
    if (!destination) {
        return std::unexpected(destination.error());
    }

    struct RestoreFileTarget {
        const NodeRow* row = nullptr;
        std::string rel_path;
    };
    std::vector<std::string> rel_dirs;
    std::vector<RestoreFileTarget> files;
    std::uint64_t total_bytes = 0;

    if (canonical_prefix.empty()) {
        for (std::size_t i = 1; i < target->tree->rows.size(); ++i) {
            const auto& row = target->tree->rows[i];
            if (row.is_directory) {
                rel_dirs.push_back(row.path);
            } else {
                total_bytes += row.size;
                files.push_back(
                    RestoreFileTarget{.row = &row, .rel_path = row.path});
            }
        }
    } else if (!root_row->is_directory) {
        const auto slash = root_row->path.rfind('/');
        const auto base_name = slash == std::string::npos
                                   ? root_row->path
                                   : root_row->path.substr(slash + 1U);
        total_bytes = root_row->size;
        files.push_back(
            RestoreFileTarget{.row = root_row, .rel_path = base_name});
    } else {
        const std::string prefix_slash = canonical_prefix + "/";
        for (std::size_t i = 1; i < target->tree->rows.size(); ++i) {
            const auto& row = target->tree->rows[i];
            if (!row.path.starts_with(prefix_slash)) {
                continue;
            }
            const auto rel = row.path.substr(prefix_slash.size());
            if (row.is_directory) {
                rel_dirs.push_back(rel);
            } else {
                total_bytes += row.size;
                files.push_back(
                    RestoreFileTarget{.row = &row, .rel_path = rel});
            }
        }
    }

    RemoteRestoreReport report{
        .dry_run = request.dry_run,
        .commit_id = target->commit_id,
        .observed_height = target->observed_height,
        .source_prefix = canonical_prefix.empty() ? "/" : canonical_prefix,
        .destination_path = platform::path::to_utf8(*destination),
        .file_count = static_cast<std::uint64_t>(files.size()),
        .directory_count = static_cast<std::uint64_t>(rel_dirs.size()),
        .total_bytes = total_bytes,
    };
    if (request.dry_run) {
        return report;
    }

    {
        std::error_code dir_ec;
        if (!std::filesystem::exists(*destination, dir_ec) &&
            !std::filesystem::create_directory(*destination, dir_ec)) {
            return dest_fail(operation,
                             "failed to create restore destination directory");
        }
        const auto st = std::filesystem::symlink_status(*destination, dir_ec);
        if (dir_ec || std::filesystem::is_symlink(st) ||
            platform::private_storage::is_reparse_or_symlink(*destination) ||
            !std::filesystem::is_directory(st)) {
            return dest_fail(operation,
                             "restore destination is not a safe directory");
        }
    }

    for (const auto& rel_dir : rel_dirs) {
        const auto target_dir =
            *destination / platform::path::from_utf8(rel_dir);
        std::error_code dir_ec;
        std::filesystem::create_directories(target_dir, dir_ec);
        const auto st = std::filesystem::symlink_status(target_dir, dir_ec);
        if (dir_ec || std::filesystem::is_symlink(st) ||
            platform::private_storage::is_reparse_or_symlink(target_dir) ||
            !std::filesystem::is_directory(st)) {
            return dest_fail(operation, "failed to prepare restored directory");
        }
    }

    const auto& manifest = *target->manifest;
    std::unordered_map<std::string, std::filesystem::path> extracted_packs;
    std::unordered_map<std::string, std::filesystem::path> verified_chunks;
    std::unordered_map<std::string, std::filesystem::path> verified_files;

    std::size_t download_units = 0;
    {
        std::unordered_set<std::string> counted_hashes;
        for (const auto& item : files) {
            const auto lhex = hash_hex(item.row->hash);
            if (!counted_hashes.insert(lhex).second) {
                continue;
            }
            if (const auto* chunked =
                    history::find_chunked_file(manifest, item.row->hash)) {
                download_units += chunked->chunks.size();
            } else {
                ++download_units;
            }
        }
    }
    begin_progress_phase(
        *context.progress, Activity::Downloading, download_units);

    std::vector<std::uint8_t> copy_buf(256U * 1024U);
    crypto::secure_memory::WipeGuard copy_buf_guard{copy_buf};

    const auto materialize_plain = [&](const NodeRow& row)
        -> std::expected<std::filesystem::path, InspectionError> {
        const auto lhex = hash_hex(row.hash);
        if (const auto cached = verified_files.find(lhex);
            cached != verified_files.end()) {
            return cached->second;
        }
        if (platform::cancellation::requested()) {
            return obs_fail(operation, "restore cancelled by user");
        }

        if (const auto* packed =
                history::find_packed_blob(manifest, row.hash)) {
            const auto pack_hex = hash_hex(packed->pack_hash);
            std::filesystem::path extract_dir;
            if (const auto pack_it = extracted_packs.find(pack_hex);
                pack_it != extracted_packs.end()) {
                extract_dir = pack_it->second;
            } else {
                const auto content_id =
                    crypto::pack_identifier(context.key, packed->pack_hash);
                const auto encrypted =
                    context.workspace->root / "restore-pack.enc";
                extract_dir = context.workspace->root / ("pack-" + pack_hex);
                auto downloaded =
                    transport::get(context.storage, content_id, encrypted);
                if (!downloaded) {
                    const bool not_found = downloaded.error().code ==
                                           transport::ErrorCode::ObjectNotFound;
                    return fail(
                        operation,
                        not_found
                            ? InspectionErrorCode::RemoteContentNotFound
                            : InspectionErrorCode::RemoteObservationFailure,
                        not_found ? "remote file content not found"
                                  : "failed to download remote content");
                }
                auto verified = crypto::pack::decrypt_and_verify_pack(
                    encrypted, context.key, packed->pack_hash, &extract_dir);
                if (!verified) {
                    return fail(
                        operation,
                        InspectionErrorCode::RemoteContentInvalid,
                        "remote pack failed cryptographic authentication");
                }
                extracted_packs.emplace(pack_hex, extract_dir);
            }
            const auto extracted = extract_dir / (lhex + ".plain");
            if (!crypto::content::verify_file(extracted, lhex, row.size)) {
                return fail(
                    operation,
                    InspectionErrorCode::RemoteContentInvalid,
                    "extracted member failed cryptographic authentication");
            }
            progress_add(context.progress->work);
            verified_files.emplace(lhex, extracted);
            return extracted;
        }

        const auto plaintext = context.workspace->root / ("plain-" + lhex);
        if (const auto* chunked =
                history::find_chunked_file(manifest, row.hash)) {
            const auto enc = context.workspace->root / "restore-chunk.enc";
            std::error_code rm_ec;
            std::filesystem::remove(plaintext, rm_ec);
            auto private_out =
                platform::private_storage::create_private_file(plaintext);
            if (!private_out) {
                return dest_fail(operation,
                                 "failed to open temporary download file");
            }
            for (const auto& chunk : chunked->chunks) {
                if (platform::cancellation::requested()) {
                    static_cast<void>(
                        platform::private_storage::remove_private_file_if_owned(
                            *private_out));
                    return obs_fail(operation, "restore cancelled by user");
                }
                const auto chex = hash_hex(chunk.hash);
                std::filesystem::path chunk_plain;
                if (const auto chunk_it = verified_chunks.find(chex);
                    chunk_it != verified_chunks.end()) {
                    chunk_plain = chunk_it->second;
                } else {
                    const auto cid =
                        crypto::content_identifier(context.key, chunk.hash);
                    chunk_plain =
                        context.workspace->root / ("chunk-" + chex + ".plain");
                    auto downloaded = transport::get(context.storage, cid, enc);
                    if (!downloaded) {
                        static_cast<void>(
                            platform::private_storage::
                                remove_private_file_if_owned(*private_out));
                        const bool not_found =
                            downloaded.error().code ==
                            transport::ErrorCode::ObjectNotFound;
                        return fail(
                            operation,
                            not_found
                                ? InspectionErrorCode::RemoteContentNotFound
                                : InspectionErrorCode::RemoteObservationFailure,
                            not_found ? "remote file chunk not found"
                                      : "failed to download remote chunk");
                    }
                    if (!crypto::decrypt_file(enc, chunk_plain, context.key) ||
                        !crypto::content::verify_file(
                            chunk_plain, chex, chunk.size)) {
                        static_cast<void>(
                            platform::private_storage::
                                remove_private_file_if_owned(*private_out));
                        return fail(
                            operation,
                            InspectionErrorCode::RemoteContentInvalid,
                            "remote chunk failed cryptographic authentication");
                    }
                    verified_chunks.emplace(chex, chunk_plain);
                }
                progress_add(context.progress->work);
                bool write_failed = false;
                auto streamed = platform::private_storage::stream_regular_file(
                    chunk_plain,
                    copy_buf,
                    [&](std::span<const std::uint8_t> slab) {
                        if (!slab.empty() &&
                            !platform::private_storage::write_private_file(
                                *private_out, slab.data(), slab.size())) {
                            write_failed = true;
                            return false;
                        }
                        return true;
                    },
                    chunk.size);
                if (!streamed || write_failed) {
                    static_cast<void>(
                        platform::private_storage::remove_private_file_if_owned(
                            *private_out));
                    return dest_fail(operation,
                                     "failed to assemble remote chunks");
                }
            }
            platform::private_storage::close_private_file(*private_out);
            if (!crypto::content::verify_file(plaintext, lhex, row.size)) {
                return fail(operation,
                            InspectionErrorCode::RemoteContentInvalid,
                            "assembled remote content failed verification");
            }
            verified_files.emplace(lhex, plaintext);
            return plaintext;
        }

        const auto content_id =
            crypto::content_identifier(context.key, row.hash);
        const auto encrypted = context.workspace->root / "restore-content.enc";
        auto downloaded =
            transport::get(context.storage, content_id, encrypted);
        if (!downloaded) {
            const bool not_found =
                downloaded.error().code == transport::ErrorCode::ObjectNotFound;
            return fail(operation,
                        not_found
                            ? InspectionErrorCode::RemoteContentNotFound
                            : InspectionErrorCode::RemoteObservationFailure,
                        not_found ? "remote file content not found"
                                  : "failed to download remote content");
        }
        if (!crypto::decrypt_file(encrypted, plaintext, context.key) ||
            !crypto::content::verify_file(plaintext, lhex, row.size)) {
            return fail(operation,
                        InspectionErrorCode::RemoteContentInvalid,
                        "remote content failed cryptographic authentication");
        }
        progress_add(context.progress->work);
        verified_files.emplace(lhex, plaintext);
        return plaintext;
    };

    std::vector<std::pair<const RestoreFileTarget*, std::filesystem::path>>
        materialized;
    materialized.reserve(files.size());
    for (const auto& item : files) {
        auto plain = materialize_plain(*item.row);
        if (!plain) {
            return std::unexpected(plain.error());
        }
        materialized.emplace_back(&item, std::move(*plain));
    }

    begin_progress_phase(*context.progress, Activity::Installing, files.size());
    for (const auto& [item_ptr, src_plain] : materialized) {
        if (platform::cancellation::requested()) {
            return obs_fail(operation, "restore cancelled by user");
        }
        const auto dst_file =
            *destination / platform::path::from_utf8(item_ptr->rel_path);
        std::error_code parent_ec;
        const auto parent_dir = dst_file.parent_path();
        const auto parent_st =
            std::filesystem::symlink_status(parent_dir, parent_ec);
        if (parent_ec || std::filesystem::is_symlink(parent_st) ||
            platform::private_storage::is_reparse_or_symlink(parent_dir) ||
            !std::filesystem::is_directory(parent_st)) {
            return dest_fail(
                operation, "restore destination parent directory is not safe");
        }
        if (auto installed =
                install_remote_file(src_plain, dst_file, operation);
            !installed) {
            return std::unexpected(installed.error());
        }
        if (item_ptr->row->mtime != 0) {
            if (const auto ft =
                    platform::metadata::file_time_from_unix_nanoseconds(
                        item_ptr->row->mtime)) {
                static_cast<void>(
                    platform::metadata::set_last_write_time(dst_file, *ft));
            }
        }
        progress_add(context.progress->work);
    }

    return report;
}

std::optional<std::uint64_t> epoch_sequence(std::string_view selector) {
    std::uint64_t value = 0;
    const auto [end, code] = std::from_chars(
        selector.data(), selector.data() + selector.size(), value);
    if (code != std::errc{} || end != selector.data() + selector.size() ||
        std::to_string(value) != selector) {
        return std::nullopt;
    }
    return value;
}

RemoteEpochInfo
epoch_info(const std::vector<history_storage::epoch::VerifiedEpoch>& chain,
           std::size_t index) {
    const auto& verified = chain[index];
    RemoteEpochInfo result{
        .vault_id = verified.value.vault_id,
        .sequence = verified.reference.sequence,
        .epoch_id = verified.reference.epoch_id,
        .issued_at = verified.value.issued_at,
        .min_history_depth = verified.value.policy.min_history_depth,
        .min_history_age_hours = verified.value.policy.min_history_age_hours,
        .previous_epoch_id = verified.value.previous_epoch_id,
        .next_epoch_id = index + 1 < chain.size()
                             ? chain[index + 1].reference.epoch_id
                             : std::string{},
    };
    result.anchors.reserve(verified.value.anchors.size());
    for (const auto& anchor : verified.value.anchors) {
        result.anchors.push_back(RemoteEpochAnchorInfo{
            .commit_id = anchor.commit_id, .height = anchor.height});
    }
    return result;
}

std::expected<InspectionResponse, InspectionError>
inspect_epochs(const InspectionRequest& request,
               InspectionContext& context,
               InspectionOperation operation) {
    auto chain = history_storage::epoch::load_chain(
        context.storage, context.key, context.workspace->root);
    if (!chain) {
        return obs_fail(operation, "failed to authenticate remote Epoch chain");
    }
    if (operation == InspectionOperation::RemoteEpochs) {
        RemoteEpochsReport report;
        report.epochs.reserve(chain->size());
        for (std::size_t index = 0; index < chain->size(); ++index) {
            report.epochs.push_back(epoch_info(*chain, index));
        }
        return make_response(operation, std::move(report));
    }

    const auto& selector = *request.epoch_selector;
    const auto sequence = epoch_sequence(selector);
    const auto selected = std::ranges::find_if(*chain, [&](const auto& epoch) {
        return history::valid_commit_id(selector)
                   ? epoch.reference.epoch_id == selector
                   : sequence && epoch.reference.sequence == *sequence;
    });
    if (selected == chain->end()) {
        return fail(operation,
                    InspectionErrorCode::RemoteEpochNotFound,
                    "requested remote Epoch does not exist");
    }
    const auto index = static_cast<std::size_t>(selected - chain->begin());
    return make_response(operation,
                         RemoteEpochReport{.epoch = epoch_info(*chain, index)});
}

std::expected<RemoteContentsReport, InspectionError>
inspect_contents(const observation::history::StorageView& observed,
                 InspectionContext& context,
                 InspectionOperation operation,
                 bool audit) {
    begin_progress_phase(*context.progress, Activity::Listing);
    std::map<std::string, RemoteContentInfo> inventory;
    std::map<std::string, std::set<std::string, std::less<>>> paths;
    std::unordered_set<std::string> pack_ids;
    const auto add_rows = [&](const Snapshot& tree,
                              const history::StorageManifest& manifest,
                              bool current) {
        const auto record_entry = [&](const std::string& content_id,
                                      const std::string& logical_hash,
                                      std::uint64_t size,
                                      std::string_view logical_path,
                                      bool is_pack) {
            auto& content = inventory[content_id];
            if (content.content_id.empty()) {
                content.content_id = content_id;
                content.logical_hash = logical_hash;
                content.size = size;
                content.referenced = true;
                if (is_pack) {
                    pack_ids.insert(content_id);
                }
            } else if (!is_pack && (content.logical_hash != logical_hash ||
                                    content.size != size ||
                                    pack_ids.contains(content_id))) {
                return false;
            } else if (is_pack && (content.logical_hash != logical_hash ||
                                   !pack_ids.contains(content_id))) {
                return false;
            }
            content.current_tree = content.current_tree || current;
            auto& unique_paths = paths[content_id];
            const auto path = logical_path.empty() ? "/" : logical_path;
            const auto position = unique_paths.lower_bound(path);
            if (position == unique_paths.end() || *position != path) {
                unique_paths.emplace_hint(position, path);
            }
            return true;
        };

        for (const auto& row : tree.rows) {
            if (row.is_directory) {
                continue;
            }
            if (const auto* packed =
                    history::find_packed_blob(manifest, row.hash)) {
                if (!record_entry(
                        crypto::pack_identifier(context.key, packed->pack_hash),
                        hash_hex(packed->pack_hash),
                        row.size,
                        row.path,
                        true)) {
                    return false;
                }
            } else if (const auto* chunked =
                           history::find_chunked_file(manifest, row.hash)) {
                for (const auto& chunk : chunked->chunks) {
                    if (!record_entry(
                            crypto::content_identifier(context.key, chunk.hash),
                            hash_hex(chunk.hash),
                            chunk.size,
                            row.path,
                            false)) {
                        return false;
                    }
                }
            } else {
                if (!record_entry(
                        crypto::content_identifier(context.key, row.hash),
                        hash_hex(row.hash),
                        row.size,
                        row.path,
                        false)) {
                    return false;
                }
            }
        }
        return true;
    };
    if (!add_rows(observed.effective_tree, observed.storage_manifest, true)) {
        return obs_fail(operation, "logical content inventory is inconsistent");
    }
    for (const auto& commit : observed.reachable_commits) {
        if (!add_rows(commit.commit.tree, commit.commit.storage, false)) {
            return obs_fail(operation,
                            "history has inconsistent content metadata");
        }
    }
    for (const auto& content_id : observed.content_object_identifiers) {
        auto& content = inventory[content_id];
        content.content_id = content_id;
        content.physically_present = true;
    }

    if (audit) {
        begin_progress_phase(*context.progress,
                             Activity::Auditing,
                             observed.content_object_identifiers.size());
    }
    std::size_t audit_index = 0;
    for (auto& [unused, content] : inventory) {
        if (const auto found = paths.find(content.content_id);
            found != paths.end()) {
            content.paths.assign(found->second.begin(), found->second.end());
            paths.erase(found);
        }
        content.state = !content.physically_present
                            ? RemoteContentState::Missing
                        : content.referenced ? RemoteContentState::Present
                                             : RemoteContentState::Orphan;
        if (!audit || !content.physically_present) {
            continue;
        }

        const bool expect_pack =
            content.referenced && pack_ids.contains(content.content_id);
        auto audited = history_storage::audit_content_object(
            context.storage,
            context.key,
            content.content_id,
            content.referenced
                ? std::optional<std::string_view>{content.logical_hash}
                : std::nullopt,
            content.referenced && !expect_pack
                ? std::optional<std::uint64_t>{content.size}
                : std::nullopt,
            context.workspace->root,
            audit_index++,
            expect_pack);
        if (!audited) {
            return obs_fail(operation,
                            "failed to download object during audit");
        }
        progress_add(context.progress->work);
        if (audited->state == history_storage::ContentObjectState::Missing) {
            content.physically_present = false;
            content.state = RemoteContentState::Missing;
            continue;
        }
        if (audited->state == history_storage::ContentObjectState::Corrupt) {
            content.state = RemoteContentState::Invalid;
            continue;
        }
        if (!content.referenced) {
            content.logical_hash = std::move(audited->plaintext_hash);
            content.size = audited->size;
        }
        content.state = RemoteContentState::Valid;
    }

    RemoteContentsReport report{.audited = audit};
    report.contents.reserve(inventory.size());
    for (auto& [unused, content] : inventory) {
        report.referenced_count += content.referenced ? 1U : 0U;
        report.physical_count += content.physically_present ? 1U : 0U;
        report.missing_count +=
            content.referenced && !content.physically_present ? 1U : 0U;
        report.orphan_count +=
            !content.referenced && content.physically_present ? 1U : 0U;
        report.valid_count +=
            content.state == RemoteContentState::Valid ? 1U : 0U;
        report.invalid_count +=
            content.state == RemoteContentState::Invalid ? 1U : 0U;
        report.contents.push_back(std::move(content));
    }
    return report;
}

constexpr std::size_t maximum_physical_object_count = 1'000'000;

std::expected<std::vector<std::string>, std::string>
list_remote_identifiers(transport::Transport& storage,
                        bool allow_storage_not_found,
                        std::string_view context_label) {
    auto listed = transport::list(storage);
    if (!listed) {
        if (allow_storage_not_found &&
            listed.error().code == transport::ErrorCode::StorageNotFound) {
            return std::vector<std::string>{};
        }
        return std::unexpected("failed to list remote " +
                               std::string{context_label} + ": " +
                               transport::describe(listed.error()));
    }
    if (listed->size() > maximum_physical_object_count) {
        return std::unexpected("remote " + std::string{context_label} +
                               " exceeds defensive limit");
    }
    history_storage::detail::sort_unique(*listed);
    return std::move(*listed);
}

std::expected<std::vector<std::string>, InspectionError>
physical_objects(InspectionContext& context, InspectionOperation operation) {
    begin_progress_phase(*context.progress, Activity::Listing);
    auto listed = list_remote_identifiers(context.storage, true, "objects");
    if (!listed) {
        return obs_fail(operation, listed.error());
    }
    return std::move(*listed);
}

RemoteObjectInfo classify_object(const history_storage::RemoteLayout& layout,
                                 std::string identifier) {
    RemoteObjectInfo result{.identifier = std::move(identifier),
                            .relation = "not audited"};
    const auto& id = result.identifier;
    if (history::valid_commit_id(id)) {
        result.category = RemoteObjectCategory::Content;
        result.structurally_valid = true;
    } else if (history_storage::parse_commit_object(layout, id)) {
        result.category = RemoteObjectCategory::CommitVariant;
        result.structurally_valid = true;
    } else if (id.starts_with(layout.heads_prefix)) {
        result.category = RemoteObjectCategory::HeadMarker;
        result.structurally_valid =
            history_storage::parse_marker_object(layout, id).has_value();
    } else if (id.starts_with(layout.epochs_prefix)) {
        result.category = RemoteObjectCategory::Epoch;
        result.structurally_valid =
            history_storage::epoch::parse_object_identifier(layout, id)
                .has_value();
    } else if (id == layout.barrier_identifier) {
        result.category = RemoteObjectCategory::Barrier;
        result.structurally_valid = true;
        result.relation = "maintenance barrier";
    } else if (id.starts_with(layout.barriers_prefix)) {
        result.category = RemoteObjectCategory::Barrier;
        result.structurally_valid =
            history_storage::valid_barrier_identifier(layout, id);
        result.relation = "maintenance barrier";
    } else if (id.starts_with(layout.writers_prefix)) {
        result.category = RemoteObjectCategory::Writer;
        result.structurally_valid =
            history_storage::valid_writer_identifier(layout, id);
        result.relation = "blocks maintenance while present";
    } else if (id.starts_with(layout.probes_prefix)) {
        result.category = RemoteObjectCategory::Protocol;
        result.structurally_valid = true;
    } else if (history_storage::is_activity_object(layout, id)) {
        result.category = RemoteObjectCategory::Activity;
        result.structurally_valid =
            history_storage::activity::parse_object_identifier(layout, id)
                .has_value();
        result.relation = "operational activity record";
    } else if (id.starts_with(layout.gc_prefix)) {
        result.category = RemoteObjectCategory::Protocol;
    }
    return result;
}

RemoteObjectsReport
make_objects_report(const history_storage::RemoteLayout& layout,
                    std::vector<std::string> identifiers) {
    RemoteObjectsReport report;
    report.objects.reserve(identifiers.size());
    for (auto& identifier : identifiers) {
        auto object = classify_object(layout, std::move(identifier));
        if (object.category == RemoteObjectCategory::Unknown ||
            !object.structurally_valid) {
            ++report.unknown_count;
        }
        report.objects.push_back(std::move(object));
    }
    return report;
}

template <typename ExpectedT>
auto unwrap_inventory(ExpectedT inventory,
                      InspectionOperation operation,
                      std::string_view message)
    -> std::expected<typename ExpectedT::value_type, InspectionError> {
    if (!inventory) {
        return obs_fail(operation, std::string{message});
    }
    return std::move(*inventory);
}

struct PhysicalInventories {
    history_storage::ReachabilityInventory history;
    history_storage::ContentReachabilityInventory content;
};

std::expected<PhysicalInventories, std::string>
load_physical_inventories(transport::Transport& storage,
                          std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                          const std::vector<std::string>& identifiers,
                          const std::filesystem::path& workspace_root,
                          bool load_epochs,
                          bool require_consistent_history,
                          const char* epoch_error,
                          const char* history_error,
                          const char* content_error) {
    std::expected<history_storage::ReachabilityInventory,
                  history_storage::Error>
        history_inventory;
    if (load_epochs) {
        auto epochs = history_storage::epoch::load_chain(
            storage, key, workspace_root, identifiers);
        if (!epochs) {
            return std::unexpected(epoch_error);
        }
        history_inventory = history_storage::inventory_reachability(
            storage, key, identifiers, *epochs, workspace_root);
    } else {
        history_inventory = history_storage::inventory_reachability(
            storage, key, identifiers, workspace_root);
    }
    if (!history_inventory) {
        return std::unexpected(history_error);
    }
    if (require_consistent_history &&
        (history_inventory->logical_heads.empty() ||
         !history_inventory->missing_parent_ids.empty() ||
         !history_inventory->invalid_parent_ids.empty())) {
        return std::unexpected(
            "remote history is incomplete; inventory is inconclusive");
    }
    auto content_inventory = history_storage::inventory_content_reachability(
        storage,
        key,
        identifiers,
        *history_inventory,
        workspace_root,
        /*audit_payloads=*/false,
        /*include_references=*/false);
    if (!content_inventory) {
        return std::unexpected(content_error);
    }
    return PhysicalInventories{
        .history = std::move(*history_inventory),
        .content = std::move(*content_inventory),
    };
}

std::set<std::string_view>
ancestral_markers(const history_storage::ReachabilityInventory& inventory) {
    std::unordered_map<std::string_view,
                       const history_storage::ReachabilityCommit*>
        commits;
    commits.reserve(inventory.commits.size());
    for (const auto& commit : inventory.commits) {
        commits.emplace(commit.commit_id, &commit);
    }
    std::set<std::string_view> marked;
    for (const auto& marker : inventory.markers) {
        if (marker.state == history_storage::ReachabilityMarkerState::Valid &&
            marker.reference) {
            marked.insert(marker.reference->commit_id);
        }
    }
    std::set<std::string_view> visited;
    std::set<std::string_view> ancestral;
    std::vector<std::string_view> pending;
    for (const auto root : marked) {
        if (const auto found = commits.find(root); found != commits.end()) {
            pending.insert(pending.end(),
                           found->second->parents.begin(),
                           found->second->parents.end());
        }
        while (!pending.empty()) {
            const auto current = pending.back();
            pending.pop_back();
            if (!visited.insert(current).second) {
                continue;
            }
            if (marked.contains(current)) {
                ancestral.insert(current);
            }
            if (const auto parent = commits.find(current);
                parent != commits.end()) {
                pending.insert(pending.end(),
                               parent->second->parents.begin(),
                               parent->second->parents.end());
            }
        }
    }
    return ancestral;
}

RemoteMarkerState marker_state(history_storage::ReachabilityMarkerState state,
                               bool ancestral) {
    using S = history_storage::ReachabilityMarkerState;
    using R = RemoteMarkerState;
    if (state == S::Valid) {
        return ancestral ? R::Ancestral : R::LogicalHead;
    }
    static constexpr std::pair<S, R> kMap[] = {
        {S::InvalidPath, R::InvalidPath},
        {S::Missing, R::Missing},
        {S::InvalidMarker, R::InvalidMarker},
        {S::MissingCommit, R::MissingCommit},
        {S::InvalidCiphertext, R::InvalidCiphertext},
        {S::InvalidCommit, R::InvalidCommit},
    };
    for (const auto& [src, dst] : kMap) {
        if (src == state) {
            return dst;
        }
    }
    return R::InvalidMarker;
}

RemoteMarkersReport
make_markers_report(const history_storage::ReachabilityInventory& inventory) {
    const auto ancestral = ancestral_markers(inventory);
    RemoteMarkersReport report;
    report.markers.reserve(inventory.markers.size());
    for (const auto& marker : inventory.markers) {
        const bool is_ancestral =
            marker.reference && ancestral.contains(marker.reference->commit_id);
        const auto state = marker_state(marker.state, is_ancestral);
        report.logical_count +=
            state == RemoteMarkerState::LogicalHead ? 1U : 0U;
        report.ancestral_count +=
            state == RemoteMarkerState::Ancestral ? 1U : 0U;
        report.invalid_count += state != RemoteMarkerState::LogicalHead &&
                                        state != RemoteMarkerState::Ancestral
                                    ? 1U
                                    : 0U;
        report.markers.push_back(RemoteMarkerInfo{
            .object_identifier = marker.identifier,
            .commit_id =
                marker.reference ? marker.reference->commit_id : std::string{},
            .ciphertext_id = marker.reference ? marker.reference->ciphertext_id
                                              : std::string{},
            .state = state});
    }
    return report;
}

RemoteOrphansReport make_orphans_report(
    const history_storage::RemoteLayout& layout,
    const history_storage::ReachabilityInventory& history_inventory,
    const history_storage::ContentReachabilityInventory& content_inventory) {
    RemoteOrphansReport report;
    std::set<std::string> marked_variants;
    for (const auto& marker : history_inventory.markers) {
        if (marker.state == history_storage::ReachabilityMarkerState::Valid &&
            marker.reference) {
            marked_variants.insert(
                history_storage::commit_object(layout, *marker.reference));
        }
    }
    for (const auto& commit : history_inventory.commits) {
        if (commit.valid && !commit.reachable) {
            report.objects.push_back(
                RemoteOrphanInfo{.identifier = commit.commit_id,
                                 .kind = RemoteOrphanKind::Commit,
                                 .removal_candidate = true});
        }
        const auto valid_variants =
            std::ranges::count_if(commit.variants, [](const auto& variant) {
                return variant.state ==
                       history_storage::detail::VariantState::Valid;
            });
        for (const auto& variant : commit.variants) {
            if (variant.identifier.empty()) {
                continue;
            }
            const bool invalid =
                variant.state ==
                    history_storage::detail::VariantState::InvalidCiphertext ||
                variant.state ==
                    history_storage::detail::VariantState::InvalidCommit;
            const bool redundant =
                commit.reachable && valid_variants > 1 &&
                variant.state == history_storage::detail::VariantState::Valid &&
                !marked_variants.contains(variant.identifier);
            if (invalid || !commit.reachable || redundant) {
                report.objects.push_back(RemoteOrphanInfo{
                    .identifier = variant.identifier,
                    .kind = invalid     ? RemoteOrphanKind::InvalidVariant
                            : redundant ? RemoteOrphanKind::RedundantVariant
                                        : RemoteOrphanKind::CommitVariant,
                    .removal_candidate = true});
            }
        }
    }
    for (const auto& identifier : content_inventory.orphan_content_ids) {
        report.objects.push_back(
            RemoteOrphanInfo{.identifier = identifier,
                             .kind = RemoteOrphanKind::Content,
                             .removal_candidate = true});
    }
    for (const auto& identifier : history_inventory.orphan_epochs) {
        report.objects.push_back(
            RemoteOrphanInfo{.identifier = identifier,
                             .kind = RemoteOrphanKind::ProtectedEpoch,
                             .removal_candidate = false});
    }
    std::set<std::string> unknown{
        history_inventory.unknown_history_objects.begin(),
        history_inventory.unknown_history_objects.end()};
    unknown.insert(content_inventory.unknown_storage_objects.begin(),
                   content_inventory.unknown_storage_objects.end());
    for (const auto& identifier : unknown) {
        report.objects.push_back(
            RemoteOrphanInfo{.identifier = identifier,
                             .kind = RemoteOrphanKind::Unknown,
                             .removal_candidate = false});
    }
    std::ranges::sort(report.objects, [](const auto& left, const auto& right) {
        return std::tie(left.identifier, left.kind) <
               std::tie(right.identifier, right.kind);
    });
    return report;
}

RemoteWritersReport
make_writers_report(const history_storage::RemoteLayout& layout,
                    const std::vector<std::string>& identifiers) {
    RemoteWritersReport report;
    for (const auto& identifier : identifiers) {
        if (identifier == layout.barrier_identifier) {
            report.barriers.push_back(RemoteBarrierInfo{
                .identifier = identifier,
                .legacy = true,
                .structurally_valid = true,
            });
        } else if (identifier.starts_with(layout.barriers_prefix)) {
            const bool valid =
                history_storage::valid_barrier_identifier(layout, identifier);
            report.protocol_consistent &= valid;
            report.barriers.push_back(RemoteBarrierInfo{
                .identifier = identifier,
                .legacy = false,
                .structurally_valid = valid,
            });
        } else if (identifier.starts_with(layout.writers_prefix)) {
            const auto state =
                history_storage::valid_writer_identifier(layout, identifier)
                    ? RemoteWriterState::Indeterminate
                    : RemoteWriterState::Invalid;
            report.protocol_consistent &= state != RemoteWriterState::Invalid;
            report.writers.push_back(
                RemoteWriterInfo{.identifier = identifier, .state = state});
        } else if (identifier.starts_with(layout.gc_prefix) &&
                   identifier != layout.barrier_identifier &&
                   !identifier.starts_with(layout.barriers_prefix) &&
                   !identifier.starts_with(layout.probes_prefix)) {
            report.protocol_consistent = false;
        }
    }
    report.barrier_present = !report.barriers.empty();
    if (!report.barriers.empty()) {
        report.barrier_identifier = report.barriers.front().identifier;
    }
    report.maintenance_blocked =
        report.barrier_present || !report.writers.empty();
    return report;
}

std::expected<RemoteHealthReport, InspectionError>
make_health_report(InspectionContext& context,
                   InspectionOperation operation,
                   const std::vector<std::string>& identifiers) {
    begin_progress_phase(*context.progress, Activity::Authenticating);
    auto inventories = load_physical_inventories(
        context.storage,
        context.key,
        identifiers,
        context.workspace->root,
        true,
        false,
        "failed to authenticate Epoch continuity",
        "failed to authenticate physical history inventory",
        "failed to audit remote content reachability");
    if (!inventories) {
        return obs_fail(operation, inventories.error());
    }
    const auto markers = make_markers_report(inventories->history);
    const auto objects = make_objects_report(context.layout, identifiers);
    const auto writers = make_writers_report(context.layout, identifiers);
    const auto orphans = make_orphans_report(
        context.layout, inventories->history, inventories->content);

    RemoteHealthReport report{
        .marker_count = markers.markers.size(),
        .reachable_commit_count = inventories->history.reachable_commits.size(),
        .orphan_count = static_cast<std::size_t>(
            std::ranges::count_if(orphans.objects,
                                  [](const auto& item) {
                                      return item.removal_candidate;
                                  })),
        .missing_content_count =
            inventories->content.missing_content_ids.size(),
        .writer_count = writers.writers.size(),
        .unknown_object_count = objects.unknown_count,
    };
    report.invalid_content_count =
        static_cast<std::size_t>(std::ranges::count_if(
            inventories->content.contents, [](const auto& content) {
                return content.reachable &&
                       content.state ==
                           history_storage::ContentObjectState::Corrupt;
            }));

    const auto add_count_reason = [&](std::size_t count,
                                      std::string_view label) {
        if (count != 0) {
            report.reasons.push_back(std::string(label) + ": " +
                                     std::to_string(count));
        }
    };
    add_count_reason(markers.invalid_count, "invalid physical markers");
    add_count_reason(inventories->history.missing_parent_ids.size(),
                     "missing commit parents");
    add_count_reason(inventories->history.invalid_parent_ids.size(),
                     "invalid commit parents");
    add_count_reason(report.missing_content_count, "missing required contents");
    add_count_reason(report.invalid_content_count, "invalid required contents");
    if (!writers.protocol_consistent) {
        report.reasons.emplace_back("inconsistent maintenance protocol");
    }
    const auto critical_reason_count = report.reasons.size();
    add_count_reason(report.orphan_count, "unreachable objects");
    add_count_reason(report.unknown_object_count, "unknown objects");
    if (writers.maintenance_blocked) {
        report.reasons.emplace_back("maintenance currently blocked");
    }
    report.state = critical_reason_count != 0 ? RemoteHealthState::Critical
                   : report.reasons.empty()   ? RemoteHealthState::Healthy
                                              : RemoteHealthState::Degraded;
    return report;
}

std::expected<InspectionResponse, InspectionError>
inspect_physical(InspectionContext& context, InspectionOperation operation) {
    if (operation == InspectionOperation::RemoteMarkers) {
        auto inventory = unwrap_inventory(
            history_storage::inventory_reachability(
                context.storage, context.key, context.workspace->root),
            operation,
            "failed to authenticate physical history inventory");
        if (!inventory) {
            return std::unexpected(inventory.error());
        }
        return make_response(operation, make_markers_report(*inventory));
    }
    auto identifiers = physical_objects(context, operation);
    if (!identifiers) {
        return std::unexpected(identifiers.error());
    }
    if (operation == InspectionOperation::RemoteOrphans) {
        auto inventories = load_physical_inventories(
            context.storage,
            context.key,
            *identifiers,
            context.workspace->root,
            false,
            false,
            "",
            "failed to authenticate physical history inventory",
            "failed to audit remote content reachability");
        if (!inventories) {
            return obs_fail(operation, inventories.error());
        }
        return make_response(operation,
                             make_orphans_report(context.layout,
                                                 inventories->history,
                                                 inventories->content));
    }
    if (operation == InspectionOperation::RemoteObjects) {
        return make_response(
            operation,
            make_objects_report(context.layout, std::move(*identifiers)));
    }
    if (operation == InspectionOperation::RemoteWriters) {
        auto report = make_writers_report(context.layout, *identifiers);
        for (auto& barrier : report.barriers) {
            if (!barrier.structurally_valid) {
                continue;
            }
            std::optional<std::string_view> expected_token;
            if (!barrier.legacy && barrier.identifier.starts_with(
                                       context.layout.barriers_prefix)) {
                expected_token = std::string_view{barrier.identifier}.substr(
                    context.layout.barriers_prefix.size());
            }
            if (auto meta =
                    history_storage::maintenance_protocol::read_marker_metadata(
                        context.storage,
                        barrier.identifier,
                        "barrier",
                        expected_token,
                        context.workspace->root)) {
                barrier.machine_name = std::move(meta->machine_name);
                barrier.pid = meta->pid;
                barrier.started_at_unix = meta->started_at_unix;
            }
        }
        for (auto& writer : report.writers) {
            if (writer.state != RemoteWriterState::Indeterminate) {
                continue;
            }
            const auto expected_token =
                std::string_view{writer.identifier}.substr(
                    context.layout.writers_prefix.size());
            if (auto meta =
                    history_storage::maintenance_protocol::read_marker_metadata(
                        context.storage,
                        writer.identifier,
                        "writer",
                        expected_token,
                        context.workspace->root)) {
                writer.machine_name = std::move(meta->machine_name);
                writer.pid = meta->pid;
                writer.started_at_unix = meta->started_at_unix;
            }
        }
        return make_response(operation, std::move(report));
    }
    return make_response(operation,
                         make_health_report(context, operation, *identifiers));
}

RemoteCommitInfo
commit_info(const kasumi::history::LoadedCommit& loaded,
            const observation::history::StorageView& observed) {
    const auto contains = [&](const auto& ids) {
        return std::ranges::find(ids, loaded.id) != ids.end();
    };
    return make_commit_info(loaded,
                            contains(observed.logical_heads),
                            contains(observed.marked_heads),
                            contains(observed.ancestral_marked_heads));
}

std::expected<RemoteCommitReport, InspectionError>
make_commit_report(const InspectionRequest& request,
                   const observation::history::StorageView& observed,
                   InspectionContext& context,
                   InspectionOperation operation) {
    const auto selected_id = request.commit_id.value_or("");
    const auto selected = std::ranges::find(observed.reachable_commits,
                                            selected_id,
                                            &kasumi::history::LoadedCommit::id);
    if (selected == observed.reachable_commits.end()) {
        return fail(operation,
                    InspectionErrorCode::RemoteCommitNotFound,
                    "commit is not reachable in current remote history");
    }
    if (!valid_commit_snapshot(*selected)) {
        return obs_fail(operation, "remote commit does not have a valid tree");
    }

    const auto authenticated =
        std::ranges::find(observed.authenticated_commit_variants,
                          selected_id,
                          &history_storage::HeadReference::commit_id);
    auto inspected = history_storage::inspect_commit_variants(
        context.storage,
        context.key,
        selected_id,
        context.workspace->root,
        authenticated == observed.authenticated_commit_variants.end()
            ? std::nullopt
            : std::optional{*authenticated});
    if (!inspected) {
        return obs_fail(operation,
                        "failed to authenticate physical commit variants");
    }

    RemoteCommitReport report{.commit = commit_info(*selected, observed)};
    report.variants.reserve(inspected->size());
    using S = history_storage::PhysicalCommitVariantState;
    for (const auto& variant : *inspected) {
        report.variants.push_back(RemoteCommitVariantInfo{
            .ciphertext_id = variant.reference.ciphertext_id,
            .object_identifier = variant.identifier,
            .state = variant.state == S::Valid ? RemoteCommitVariantState::Valid
                     : variant.state == S::InvalidCommit
                         ? RemoteCommitVariantState::InvalidCommit
                         : RemoteCommitVariantState::InvalidCiphertext,
        });
    }
    return report;
}

std::expected<InspectionResponse, InspectionError>
run_inspection(InspectionInput& input,
               InspectionContext& context,
               transport::Transport* cache) {
    const auto operation = input.request.operation;
    const auto& req = input.request;
    const auto invalid = [&](std::string msg) {
        return fail(
            operation, InspectionErrorCode::InvalidRequest, std::move(msg));
    };
    if (static_cast<std::size_t>(operation) >
        static_cast<std::size_t>(InspectionOperation::RemoteRestore)) {
        return fail(operation,
                    InspectionErrorCode::RuntimeFailure,
                    "unknown inspection operation");
    }
    using Op = InspectionOperation;
    const bool allowed_selectors =
        (!req.head_commit_id || operation == Op::RemoteTree) &&
        (!req.logical_path || operation == Op::RemoteStat ||
         operation == Op::RemoteGet || operation == Op::RemoteLog ||
         operation == Op::RemoteRestore) &&
        (!req.download_slice || operation == Op::RemoteGet) &&
        !(req.head_commit_id && req.commit_id) &&
        (!req.commit_id || operation == Op::RemoteTree ||
         operation == Op::RemoteCommit || operation == Op::RemoteStat ||
         operation == Op::RemoteGet || operation == Op::RemoteRestore) &&
        (!req.destination_path || operation == Op::RemoteGet ||
         operation == Op::RemoteRestore) &&
        (!req.epoch_selector || operation == Op::RemoteEpoch) &&
        (!req.content_id || operation == Op::RemoteContent) &&
        (!req.dry_run || operation == Op::RemoteRestore);
    if (!allowed_selectors) {
        return invalid(
            "selector does not belong to requested inspection operation");
    }
    if (operation == Op::RemoteStat &&
        (!req.logical_path || !valid_logical_path(*req.logical_path))) {
        return invalid("requested logical path is invalid");
    }
    if (operation == Op::RemoteLog &&
        (!req.logical_path || !kasumi::valid_logical_path(*req.logical_path))) {
        return invalid("requested logical path is invalid");
    }
    if (operation == Op::RemoteGet &&
        (!req.logical_path || !kasumi::valid_logical_path(*req.logical_path) ||
         !req.destination_path || req.destination_path->empty())) {
        return invalid("remote path or destination is invalid");
    }
    if (operation == Op::RemoteRestore &&
        (!req.destination_path || req.destination_path->empty() ||
         (req.logical_path && !valid_logical_path(*req.logical_path)))) {
        return invalid("remote prefix or destination is invalid");
    }
    if (operation == Op::RemoteCommit &&
        (!req.commit_id || !history::valid_commit_id(*req.commit_id))) {
        return invalid("requested commit ID is invalid");
    }
    if ((operation == Op::RemoteTree || operation == Op::RemoteStat ||
         operation == Op::RemoteGet || operation == Op::RemoteRestore) &&
        req.commit_id && !history::valid_commit_id(*req.commit_id)) {
        return invalid("requested commit ID is invalid");
    }
    if (operation == Op::RemoteContent &&
        (!req.content_id || !history::valid_commit_id(*req.content_id))) {
        return invalid("requested content ID is invalid");
    }
    if (operation == Op::RemoteEpoch &&
        (!req.epoch_selector ||
         (!history::valid_commit_id(*req.epoch_selector) &&
          !epoch_sequence(*req.epoch_selector)))) {
        return invalid("requested Epoch ID or sequence is invalid");
    }
    if (req.transfer_concurrency &&
        (*req.transfer_concurrency < 1U ||
         *req.transfer_concurrency >
             maximum_experimental_content_concurrency)) {
        return invalid("--concurrency must be between 1 and 16");
    }
    if (req.bandwidth_limit) {
        if (const auto valid_bw =
                transport::validate_bandwidth_limit(*req.bandwidth_limit);
            !valid_bw) {
            return invalid(valid_bw.error().message);
        }
    }

    auto runtime_data = runtime::resolve(input.environment.app_data_dir,
                                         input.request.profile_name,
                                         runtime::AccessMode::ReadOnly,
                                         false);
    if (!runtime_data) {
        return std::unexpected(
            map_runtime_error(operation, runtime_data.error()));
    }
    context.runtime = *runtime_data;

    const ScopedContentConcurrency concurrency_scope{
        resolve_content_concurrency(req.transfer_concurrency,
                                    context.runtime.transfer_concurrency)};

    auto key =
        resolve_key(input.credentials, context.runtime, context.key, operation);
    if (!key) {
        return std::unexpected(key.error());
    }
    context.layout = history_storage::derive_remote_layout(context.key);

    context.hints =
        make_observation_hints(context.runtime, operation, context.layout);

    if (cache && transport::valid(*cache)) {
        context.storage = transport::borrow_transport(*cache);
    } else {
        auto opened = transport::open_transport(
            context.runtime.storage_location,
            transport::TransportOptions{
                .forbidden_executable_root = context.runtime.local_dir,
                .rclone_config = context.runtime.rclone_config,
                .bandwidth_limit = req.bandwidth_limit
                                       ? req.bandwidth_limit
                                       : context.runtime.bandwidth_limit,
            });
        if (!opened) {
            return fail(operation,
                        InspectionErrorCode::RuntimeFailure,
                        "failed to open remote storage");
        }
        if (cache) {
            *cache = std::move(*opened);
            context.storage = transport::borrow_transport(*cache);
        } else
            context.storage = std::move(*opened);
    }

    ProgressMeter meter(input.on_progress,
                        context.storage,
                        static_cast<bool>(input.on_progress));
    context.progress = &meter;
    begin_progress_phase(meter, Activity::Listing);

    auto workspace = platform::create_workspace("remote-inspection");
    if (!workspace) {
        return obs_fail(operation, "failed to prepare remote observation");
    }
    context.workspace = std::move(*workspace);

    if (operation == Op::RemoteEpochs || operation == Op::RemoteEpoch) {
        return inspect_epochs(input.request, context, operation);
    }
    if (operation == Op::RemoteMarkers || operation == Op::RemoteObjects ||
        operation == Op::RemoteOrphans || operation == Op::RemoteWriters ||
        operation == Op::RemoteHealth) {
        return inspect_physical(context, operation);
    }

    const bool audit_content_objects =
        operation == Op::RemoteSummary || operation == Op::RemoteContents ||
        operation == Op::RemoteContentsAudit || operation == Op::RemoteContent;
    const bool need_complete_history =
        requires_complete_history(operation) ||
        ((operation == Op::RemoteTree || operation == Op::RemoteStat ||
          operation == Op::RemoteGet || operation == Op::RemoteRestore) &&
         input.request.commit_id.has_value());
    begin_progress_phase(meter, Activity::Authenticating);
    auto observed = observation::history::observe(
        context.storage,
        context.key,
        context.workspace->root,
        audit_content_objects,
        need_complete_history
            ? nullptr
            : (context.hints.frontier ? &*context.hints.frontier : nullptr),
        context.hints.trusted_marker_identifiers,
        need_complete_history);
    if (!observed) {
        return obs_fail(operation, "failed to observe remote history");
    }

    meter.work.store(observed->reachable_commits.size(),
                     std::memory_order_relaxed);
    if (operation == Op::RemoteContents ||
        operation == Op::RemoteContentsAudit ||
        operation == Op::RemoteContent) {
        auto contents = inspect_contents(*observed,
                                         context,
                                         operation,
                                         operation == Op::RemoteContentsAudit);
        if (!contents || operation != Op::RemoteContent) {
            return make_response(operation, std::move(contents));
        }
        const auto selected = std::ranges::find(contents->contents,
                                                *input.request.content_id,
                                                &RemoteContentInfo::content_id);
        if (selected == contents->contents.end()) {
            return fail(
                operation,
                InspectionErrorCode::RemoteContentNotFound,
                "requested content ID does not exist in remote inventory");
        }
        return make_response(
            operation, RemoteContentReport{.content = std::move(*selected)});
    }

    if (operation == Op::RemoteSummary) {
        auto writers = history_storage::maintenance_protocol::active_writers(
            context.storage, context.layout);
        if (!writers) {
            return obs_fail(operation, "failed to observe remote writers");
        }
        auto activities =
            history_storage::activity::load_all(context.storage,
                                                context.layout,
                                                context.key,
                                                context.workspace->root);
        if (!activities) {
            return obs_fail(operation,
                            "failed to observe remote operational activity");
        }
        std::vector<RemoteActivityInfo> recent;
        recent.reserve(activities->valid.size());
        for (const auto& entry : activities->valid) {
            const auto& rec = entry.record;
            recent.push_back(RemoteActivityInfo{
                .event_id = rec.event_id,
                .operation =
                    static_cast<RemoteActivityOperation>(rec.operation),
                .outcome = static_cast<RemoteActivityOutcome>(rec.outcome),
                .machine_id_hex = encode_machine_id_hex(rec.machine_id),
                .machine_name = rec.machine_name,
                .started_at = rec.started_at,
                .finished_at = rec.finished_at,
                .duration_ms = rec.duration_ms,
                .metric_primary = rec.metric_primary,
                .metric_secondary = rec.metric_secondary,
                .metric_bytes = rec.metric_bytes,
                .flags = rec.flags,
                .stage = rec.stage,
                .detail = rec.detail,
            });
        }
        std::ranges::sort(recent, [](const auto& left, const auto& right) {
            if (left.finished_at != right.finished_at) {
                return left.finished_at > right.finished_at;
            }
            return left.event_id < right.event_id;
        });
        std::optional<RemoteSpaceUsage> usage;
        if (req.include_space_usage) {
            auto inventory =
                inspect_contents(*observed, context, operation, false);
            if (!inventory)
                return std::unexpected(inventory.error());
            auto listing = transport::list_metadata(context.storage);
            if (!listing)
                return obs_fail(operation,
                                "failed to list physical content sizes");
            std::unordered_map<std::string_view, std::uint64_t> sizes;
            for (const auto& obj : *listing)
                if (obj.size)
                    sizes.emplace(obj.identifier, *obj.size);
            usage.emplace();
            for (const auto& obj : inventory->contents) {
                if (!obj.physically_present)
                    continue;
                auto it = sizes.find(obj.content_id);
                if (it == sizes.end())
                    ++usage->unknown_sizes;
                else if (obj.current_tree)
                    usage->current_content_bytes += it->second;
                else if (obj.referenced)
                    usage->retained_content_bytes += it->second;
                else
                    usage->orphan_content_bytes += it->second;
            }
        }
        return make_response(
            operation,
            RemoteSummaryReport{
                .history_present = observed->history_present,
                .observed_height = observed->observed_height,
                .reachable_commit_count = observed->reachable_commit_ids.size(),
                .logical_head_count = observed->logical_heads.size(),
                .has_conflicts = observed->has_conflicts,
                .missing_content_count = observed->missing_content_count,
                .orphan_content_count = observed->orphan_content_count,
                .active_writer_count = writers->size(),
                .recent_activities = std::move(recent),
                .invalid_activity_count = activities->invalid_objects.size(),
                .space_usage = usage,
            });
    }

    if (operation == Op::RemoteHeads || operation == Op::RemoteTree) {
        auto heads = make_head_infos(*observed, operation);
        if (!heads) {
            return std::unexpected(heads.error());
        }
        if (operation == Op::RemoteTree) {
            return make_response(
                operation,
                make_tree_report(input.request, *observed, *heads, operation));
        }
        return make_response(operation,
                             RemoteHeadsReport{
                                 .history_present = observed->history_present,
                                 .observed_height = observed->observed_height,
                                 .physical_marker_count =
                                     observed->marked_head_identifiers.size(),
                                 .ancestral_marker_count =
                                     observed->ancestral_marked_heads.size(),
                                 .heads = std::move(*heads),
                             });
    }

    if (operation == Op::RemoteStat) {
        return make_response(
            operation, make_stat_report(input.request, *observed, operation));
    }
    if (operation == Op::RemoteLog) {
        return make_response(
            operation, make_log_report(input.request, *observed, operation));
    }
    if (operation == Op::RemoteCommit) {
        return make_response(
            operation,
            make_commit_report(input.request, *observed, context, operation));
    }
    if (operation == Op::RemoteGet) {
        return make_response(
            operation,
            download_remote_file(input.request, *observed, context, operation));
    }
    if (operation == Op::RemoteRestore) {
        return make_response(
            operation,
            restore_remote_tree(input.request, *observed, context, operation));
    }
    return make_response(operation, make_commits_report(*observed, operation));
}

void finish_inspection(InspectionInput& input, InspectionContext& context) {
    if (context.workspace) {
        platform::cleanup_workspace(*context.workspace);
        context.workspace.reset();
    }
    context.storage = {};
    crypto::secure_memory::wipe(context.key.data(), context.key.size());
    wipe_credentials(input.credentials);
}

} // namespace

std::expected<InventoryAuditReport, std::string>
audit_remote_inventory(transport::Transport& storage,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    auto workspace = platform::create_workspace("sync-inventory-audit");
    if (!workspace) {
        return std::unexpected("failed to prepare remote inventory audit");
    }
    struct Guard {
        platform::Workspace& workspace;
        ~Guard() {
            platform::cleanup_workspace(workspace);
        }
    } guard{*workspace};

    try {
        const auto identifiers =
            list_remote_identifiers(storage, false, "inventory");
        if (!identifiers) {
            return std::unexpected(identifiers.error());
        }
        const auto layout = history_storage::derive_remote_layout(key);
        const auto writers = make_writers_report(layout, *identifiers);
        if (writers.maintenance_blocked || !writers.protocol_consistent) {
            return std::unexpected("remote inventory is inconclusive while "
                                   "maintenance or a writer is active");
        }
        auto inventories = load_physical_inventories(
            storage,
            key,
            *identifiers,
            workspace->root,
            true,
            true,
            "failed to authenticate remote Epoch history",
            "failed to authenticate remote history inventory",
            "failed to classify remote content reachability");
        if (!inventories) {
            return std::unexpected(inventories.error());
        }
        const auto objects = make_objects_report(layout, *identifiers);
        const auto unchanged =
            list_remote_identifiers(storage, false, "inventory");
        if (!unchanged) {
            return std::unexpected(unchanged.error());
        }
        if (*identifiers != *unchanged) {
            return std::unexpected("remote inventory changed during audit; "
                                   "results are inconclusive");
        }
        const auto& content = inventories->content;
        if (content.missing_content_ids.size() >
            content.reachable_content_ids.size()) {
            return std::unexpected(
                "remote content inventory is internally inconsistent");
        }
        return InventoryAuditReport{
            .referenced_content = content.reachable_content_ids.size(),
            .present_content = content.reachable_content_ids.size() -
                               content.missing_content_ids.size(),
            .missing_content = content.missing_content_ids.size(),
            .orphan_content = content.orphan_content_ids.size(),
            .unknown_objects = objects.unknown_count,
        };
    } catch (...) {
        return std::unexpected("exception during remote inventory audit");
    }
}

std::expected<InspectionResponse, InspectionError>
inspect(InspectionInput input) {
    const platform::cancellation::ScopedStopToken stop_scope{input.stop_token};
    platform::perf_trace::reset();
    const auto total_trace = platform::perf_trace::begin();
    InspectionContext context;
    std::expected<InspectionResponse, InspectionError> result =
        std::unexpected(error(input.request.operation,
                              InspectionErrorCode::RuntimeFailure,
                              "remote inspection failure"));
    try {
        result = run_inspection(input, context, input.transport_cache);
    } catch (...) {
        result = std::unexpected(error(input.request.operation,
                                       InspectionErrorCode::RuntimeFailure,
                                       "exception during remote inspection"));
    }
    finish_inspection(input, context);
    platform::perf_trace::finish("total inspection", total_trace);
    platform::perf_trace::report(result ? "inspection-success"
                                        : "inspection-error");
    return result;
}

struct RemoteDownloadSessionState {
    std::mutex mutex;
    std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    transport::Transport storage{};
    std::optional<platform::Workspace> workspace;
    RemoteStatReport stat;
    RemoteDownloadTarget target;
    std::size_t content_concurrency = 1;
    std::unordered_map<std::string, std::filesystem::path> verified_chunks;
    std::deque<std::string> verified_chunk_order;
};

void destroy_remote_download_session(RemoteDownloadSessionState* state) noexcept {
    if (!state) {
        return;
    }
    if (state->workspace) {
        platform::cleanup_workspace(*state->workspace);
        state->workspace.reset();
    }
    state->storage = {};
    crypto::secure_memory::wipe(state->key.data(), state->key.size());
    delete state;
}

std::expected<RemoteDownloadSession, InspectionError>
open_remote_download(InspectionInput input) {
    const auto operation = InspectionOperation::RemoteGet;
    try {
        struct CredentialWiper {
            Credentials& creds;
            ~CredentialWiper() {
                wipe_credentials(creds);
            }
        } wiper{input.credentials};

        const platform::cancellation::ScopedStopToken stop_scope{
            input.stop_token};
        const auto& req = input.request;
        const auto invalid = [&](std::string msg) {
            return fail(
                operation, InspectionErrorCode::InvalidRequest, std::move(msg));
        };
        if (!req.logical_path || !kasumi::valid_logical_path(*req.logical_path)) {
            return invalid("remote path is invalid");
        }
        if (req.head_commit_id || req.content_id || req.epoch_selector ||
            req.dry_run) {
            return invalid(
                "selector does not belong to requested download session");
        }
        if (req.commit_id && !history::valid_commit_id(*req.commit_id)) {
            return invalid("requested commit ID is invalid");
        }
        if (req.transfer_concurrency &&
            (*req.transfer_concurrency < 1U ||
             *req.transfer_concurrency >
                 maximum_experimental_content_concurrency)) {
            return invalid("--concurrency must be between 1 and 16");
        }
        if (req.bandwidth_limit) {
            if (const auto valid_bw =
                    transport::validate_bandwidth_limit(*req.bandwidth_limit);
                !valid_bw) {
                return invalid(valid_bw.error().message);
            }
        }

        auto runtime_data = runtime::resolve(input.environment.app_data_dir,
                                             req.profile_name,
                                             runtime::AccessMode::ReadOnly,
                                             false);
        if (!runtime_data) {
            return std::unexpected(
                map_runtime_error(operation, runtime_data.error()));
        }

        RemoteDownloadSession session{
            .state = {new RemoteDownloadSessionState(),
                      &destroy_remote_download_session}};
        session.state->content_concurrency = resolve_content_concurrency(
            req.transfer_concurrency, runtime_data->transfer_concurrency);
        const ScopedContentConcurrency concurrency_scope{
            session.state->content_concurrency};

        auto key = resolve_key(
            input.credentials, *runtime_data, session.state->key, operation);
        if (!key) {
            return std::unexpected(key.error());
        }
        const auto layout =
            history_storage::derive_remote_layout(session.state->key);
        const auto hints =
            make_observation_hints(*runtime_data, operation, layout);

        const bool borrowed_transport =
            input.transport_cache && transport::valid(*input.transport_cache);
        if (borrowed_transport) {
            session.state->storage = std::move(*input.transport_cache);
        } else {
            auto opened = transport::open_transport(
                runtime_data->storage_location,
                transport::TransportOptions{
                    .forbidden_executable_root = runtime_data->local_dir,
                    .rclone_config = runtime_data->rclone_config,
                    .bandwidth_limit = req.bandwidth_limit
                                           ? req.bandwidth_limit
                                           : runtime_data->bandwidth_limit,
                });
            if (!opened) {
                return fail(operation,
                            InspectionErrorCode::RuntimeFailure,
                            "failed to open remote storage");
            }
            session.state->storage = std::move(*opened);
        }

        auto workspace = platform::create_workspace("remote-download");
        if (!workspace) {
            if (borrowed_transport &&
                transport::valid(session.state->storage)) {
                *input.transport_cache = std::move(session.state->storage);
                session.state->storage = {};
            }
            return obs_fail(operation, "failed to prepare remote observation");
        }
        session.state->workspace = std::move(*workspace);

        const bool need_complete_history = req.commit_id.has_value();
        auto observed = observation::history::observe(
            session.state->storage,
            session.state->key,
            session.state->workspace->root,
            false,
            need_complete_history
                ? nullptr
                : (hints.frontier ? &*hints.frontier : nullptr),
            hints.trusted_marker_identifiers,
            need_complete_history);
        if (!observed) {
            return obs_fail(operation, "failed to observe remote history");
        }

        auto resolved = resolve_remote_file_target(
            req, *observed, operation, *req.logical_path);
        if (!resolved) {
            if (borrowed_transport &&
                transport::valid(session.state->storage)) {
                *input.transport_cache = std::move(session.state->storage);
                session.state->storage = {};
            }
            return std::unexpected(resolved.error());
        }

        const auto* row = resolved->row;
        RemoteStatReport stat{
            .observed_height = resolved->commit.observed_height,
            .has_conflicts = resolved->commit.has_conflicts,
            .commit_id = resolved->commit.commit_id,
            .path = row->path.empty() ? "/" : row->path,
            .type = RemoteTreeEntryType::File,
            .logical_hash = hash_hex(row->hash),
            .size = row->size,
            .modified_at_unix_nanoseconds = row->mtime,
        };
        if (resolved->commit.manifest) {
            if (const auto* packed = history::find_packed_blob(
                    *resolved->commit.manifest, row->hash))
                stat.pack_hash = hash_hex(packed->pack_hash);
            if (const auto* chunk_layout = history::find_chunked_file(
                    *resolved->commit.manifest, row->hash)) {
                for (const auto& chunk : chunk_layout->chunks)
                    stat.chunks.push_back({hash_hex(chunk.hash), chunk.size});
            }
        }
        session.state->stat = std::move(stat);
        session.state->target = make_download_target(
            *row,
            *resolved->commit.manifest,
            session.state->key,
            resolved->commit.commit_id);
        return session;
    } catch (...) {
        return fail(operation,
                    InspectionErrorCode::RuntimeFailure,
                    "exception while opening remote download");
    }
}

const RemoteStatReport&
remote_download_stat(const RemoteDownloadSession& session) noexcept {
    static const RemoteStatReport kEmpty{};
    return session.state ? session.state->stat : kEmpty;
}

std::expected<RemoteFileReport, InspectionError>
read_remote_download_slice(RemoteDownloadSession& session,
                           const std::filesystem::path& destination_path,
                           std::optional<DownloadSlice> slice,
                           std::stop_token stop) {
    const auto operation = InspectionOperation::RemoteGet;
    try {
        if (!session.state) {
            return fail(operation,
                        InspectionErrorCode::RuntimeFailure,
                        "remote download session is closed");
        }
        std::lock_guard lock(session.state->mutex);
        if (!session.state->workspace ||
            !transport::valid(session.state->storage)) {
            return fail(operation,
                        InspectionErrorCode::RuntimeFailure,
                        "remote download session is closed");
        }
        const platform::cancellation::ScopedStopToken stop_scope{stop};
        const ScopedContentConcurrency concurrency_scope{
            session.state->content_concurrency};

        auto destination =
            resolve_destination_path(destination_path, operation);
        if (!destination) {
            return std::unexpected(destination.error());
        }
        return download_target_to_destination(
            session.state->storage,
            session.state->key,
            session.state->workspace->root,
            nullptr,
            operation,
            session.state->target,
            *destination,
            slice,
            &session.state->verified_chunks,
            &session.state->verified_chunk_order,
            /*allow_cache_plaintext=*/true);
    } catch (...) {
        return fail(operation,
                    InspectionErrorCode::RuntimeFailure,
                    "exception during remote download");
    }
}

std::optional<transport::Transport>
take_remote_download_transport(RemoteDownloadSession& session) noexcept {
    if (!session.state) {
        return std::nullopt;
    }
    std::lock_guard lock(session.state->mutex);
    if (!transport::valid(session.state->storage)) {
        return std::nullopt;
    }
    transport::Transport taken = std::move(session.state->storage);
    session.state->storage = {};
    return taken;
}

} // namespace kasumi::application
