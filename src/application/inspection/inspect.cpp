#include "application/inspection/inspect.hpp"

#include "application/detail.hpp"
#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/detail.hpp"
#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/history.hpp"
#include "core/node.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/secure_memory.hpp"
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
#include <exception>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace kasumi::application {
namespace {

struct InspectionObservationHints {
    std::optional<history_storage::KnownHistoryFrontier> frontier;
    std::vector<std::string> trusted_marker_identifiers;
};

struct InspectionContext {
    runtime::RuntimeData runtime;
    runtime::vault::KeyBytes key{};
    history_storage::RemoteLayout layout{};
    transport::Transport storage{};
    std::optional<platform::Workspace> workspace;
    InspectionObservationHints hints;
};

bool requires_complete_history(InspectionOperation operation) noexcept {
    return operation == InspectionOperation::RemoteCommits ||
           operation == InspectionOperation::RemoteSummary ||
           operation == InspectionOperation::RemoteCommit ||
           operation == InspectionOperation::RemoteContents ||
           operation == InspectionOperation::RemoteContentsAudit ||
           operation == InspectionOperation::RemoteContent;
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

InspectionObservationHints
make_observation_hints(const runtime::RuntimeData& runtime_data,
                       InspectionOperation operation,
                       const history_storage::RemoteLayout& layout) {
    InspectionObservationHints hints;
    auto persisted = state_storage::load_state(runtime_data.database_path);
    if (!persisted || !*persisted) {
        return hints;
    }

    auto& state = **persisted;
    if (operation == InspectionOperation::RemoteHeads ||
        operation == InspectionOperation::RemoteTree ||
        operation == InspectionOperation::RemoteStat ||
        operation == InspectionOperation::RemoteGet) {
        hints.frontier.emplace();
        hints.frontier->anchors.push_back(history_storage::KnownHistoryAnchor{
            .commit_id = state.commit_id,
            .height = state.height,
            .tree = std::move(state.tree),
        });
        if (!state.epoch_id.empty()) {
            hints.frontier->accepted_epoch = history_storage::epoch::Reference{
                .sequence = state.epoch_sequence,
                .epoch_id = state.epoch_id,
            };
        }
    }

    if (!state.ciphertext_id.empty()) {
        const history_storage::HeadReference reference{
            .commit_id = state.commit_id,
            .ciphertext_id = state.ciphertext_id,
        };
        if (history_storage::valid(reference)) {
            hints.trusted_marker_identifiers.push_back(
                history_storage::marker_object(layout, reference));
        }
    }
    return hints;
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
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::RemoteObservationFailure,
                      "remote history contains duplicate commit"));
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

std::expected<RemoteHeadInfo, InspectionError>
make_head_info(std::string_view id,
               const ObservedCommitIndex& commits,
               InspectionOperation operation) {
    const auto observed = commits.find(id);
    if (observed == commits.end() ||
        !valid_commit_snapshot(*observed->second)) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "logical head does not have a valid observed commit"));
    }
    const auto* match = observed->second;
    const auto& tree = match->commit.tree;
    RemoteHeadInfo result{.commit_id = match->id,
                          .height = match->commit.height,
                          .created_at = match->commit.created_at,
                          .parent_ids = match->commit.parents,
                          .root_hash = hash_hex(tree.rows.front().hash),
                          .total_bytes = tree.rows.front().size};
    for (std::size_t index = 1; index < tree.rows.size(); ++index) {
        if (tree.rows[index].is_directory) {
            ++result.directory_count;
        } else {
            ++result.file_count;
        }
    }
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
        if (request.head_commit_id) {
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::RemoteHeadNotFound,
                      "requested head is not among current logical heads"));
        }
        return report;
    }

    if (heads.empty()) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "remote history has no observed logical head"));
    }

    std::string selected_id;
    if (request.head_commit_id) {
        const auto selected =
            std::ranges::find(observed.logical_heads, *request.head_commit_id);
        if (selected == observed.logical_heads.end()) {
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::RemoteHeadNotFound,
                      "requested head is not among current logical heads",
                      head_ids(heads)));
        }
        selected_id = *selected;
    } else {
        if (heads.size() > 1) {
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::HeadSelectionRequired,
                      "Remote history has multiple logical heads.",
                      head_ids(heads)));
        }
        selected_id = heads.front().commit_id;
    }

    const auto selected = std::ranges::find(
        observed.reachable_commits, selected_id, &history::LoadedCommit::id);
    if (selected == observed.reachable_commits.end() ||
        !valid_commit_snapshot(*selected)) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "logical head does not have a valid observed commit"));
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
        if (row.is_directory) {
            ++report.directory_count;
        } else {
            ++report.file_count;
        }
    }
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
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "remote history has no observed reachable commits"));
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
        const auto& rows = loaded.commit.tree.rows;
        if (rows.empty()) {
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::RemoteObservationFailure,
                      "remote history contains commit without tree"));
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
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "remote resolution references unreachable head"));
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
        if (left.height != right.height) {
            return left.height > right.height;
        }
        if (left.created_at != right.created_at) {
            return left.created_at > right.created_at;
        }
        return left.commit_id < right.commit_id;
    });
    return report;
}

bool valid_logical_path(std::string_view path) {
    return path == "/" || kasumi::valid_logical_path(path);
}

std::expected<RemoteStatReport, InspectionError>
make_stat_report(const InspectionRequest& request,
                 const observation::history::StorageView& observed,
                 InspectionOperation operation) {
    const auto requested = request.logical_path.value_or("");
    if (!valid_logical_path(requested)) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::InvalidRequest,
                                     "requested logical path is invalid"));
    }
    const auto canonical = requested == "/" ? std::string_view{} : requested;
    const auto* row = observed.history_present
                          ? find_row(observed.effective_tree, canonical)
                          : nullptr;
    if (row == nullptr) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::RemotePathNotFound,
                                     "path does not exist in remote logical "
                                     "tree"));
    }
    return RemoteStatReport{
        .observed_height = observed.observed_height,
        .has_conflicts = observed.has_conflicts,
        .path = row->path.empty() ? "/" : row->path,
        .type = row->is_directory ? RemoteTreeEntryType::Directory
                                  : RemoteTreeEntryType::File,
        .logical_hash = hash_hex(row->hash),
        .size = row->size,
        .modified_at_unix_nanoseconds = row->mtime,
    };
}

std::expected<std::filesystem::path, InspectionError>
resolve_destination(const InspectionRequest& request,
                    InspectionOperation operation) {
    const auto requested = request.destination_path.value_or("");
    if (requested.empty()) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::InvalidRequest,
                                     "requested destination is invalid"));
    }
    std::error_code filesystem_error;
    auto destination =
        std::filesystem::absolute(platform::path::from_utf8(requested),
                                  filesystem_error)
            .lexically_normal();
    if (filesystem_error || destination.filename().empty()) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::DestinationFailure,
                                     "failed to resolve destination"));
    }
    const auto parent_status = std::filesystem::symlink_status(
        destination.parent_path(), filesystem_error);
    if (filesystem_error || std::filesystem::is_symlink(parent_status) ||
        !std::filesystem::is_directory(parent_status)) {
        return std::unexpected(error(
            operation,
            InspectionErrorCode::DestinationFailure,
            "destination parent directory does not exist or is not safe"));
    }
    const auto destination_status =
        std::filesystem::symlink_status(destination, filesystem_error);
    if (filesystem_error == std::errc::no_such_file_or_directory) {
        filesystem_error.clear();
    } else if (filesystem_error ||
               std::filesystem::is_symlink(destination_status) ||
               std::filesystem::is_directory(destination_status) ||
               (!std::filesystem::is_regular_file(destination_status) &&
                destination_status.type() !=
                    std::filesystem::file_type::not_found)) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::DestinationFailure,
                                     "destination is not a safe regular file"));
    }
    return destination;
}

std::expected<void, InspectionError>
install_remote_file(const std::filesystem::path& plaintext,
                    const std::filesystem::path& destination,
                    InspectionOperation operation) {
    auto token = platform::random::hex_id();
    if (!token) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::DestinationFailure,
                                     "failed to prepare destination"));
    }
    const auto temporary =
        destination.parent_path() / (".kasumi-download-" + *token + ".tmp");
    auto private_tmp =
        platform::private_storage::create_private_file(temporary);
    if (!private_tmp) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::DestinationFailure,
                                     "failed to prepare destination file"));
    }
    const auto cleanup = [&] {
        static_cast<void>(
            platform::private_storage::remove_private_file_if_owned(
                *private_tmp));
    };
    std::array<std::uint8_t, 65536> buffer{};
    std::expected<void, InspectionError> write_error;
    const auto streamed = platform::private_storage::stream_regular_file(
        plaintext, buffer, [&](std::span<const std::uint8_t> chunk) {
            if (auto written = platform::private_storage::write_private_file(
                    *private_tmp, chunk.data(), chunk.size());
                !written) {
                write_error = std::unexpected(
                    error(operation,
                          InspectionErrorCode::DestinationFailure,
                          "failed to prepare destination file"));
                return false;
            }
            return true;
        });
    if (!write_error) {
        cleanup();
        return write_error;
    }
    if (!streamed) {
        cleanup();
        return std::unexpected(error(operation,
                                     InspectionErrorCode::DestinationFailure,
                                     "failed to read downloaded file"));
    }
    if (auto published = platform::private_storage::publish_private_file(
            *private_tmp, destination);
        !published) {
        cleanup();
        return std::unexpected(error(operation,
                                     InspectionErrorCode::DestinationFailure,
                                     "failed to install download"));
    }
    return {};
}

std::expected<RemoteFileReport, InspectionError>
download_remote_file(const InspectionRequest& request,
                     const observation::history::StorageView& observed,
                     InspectionContext& context,
                     InspectionOperation operation) {
    const auto* row = observed.history_present
                          ? find_row(observed.effective_tree,
                                     request.logical_path.value_or(""))
                          : nullptr;
    if (row == nullptr) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::RemotePathNotFound,
                                     "path does not exist in remote logical "
                                     "tree"));
    }
    if (row->is_directory) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::RemotePathIsDirectory,
                                     "remote path is a directory"));
    }
    auto destination = resolve_destination(request, operation);
    if (!destination) {
        return std::unexpected(destination.error());
    }

    const auto logical_hash = hash_hex(row->hash);
    const auto content_id = crypto::content_identifier(context.key, row->hash);
    const auto encrypted = context.workspace->root / "remote-content.enc";
    const auto plaintext = context.workspace->root / "remote-content.plain";
    auto downloaded = transport::get(context.storage, content_id, encrypted);
    if (!downloaded) {
        const auto code =
            downloaded.error().code == transport::ErrorCode::ObjectNotFound
                ? InspectionErrorCode::RemoteContentNotFound
                : InspectionErrorCode::RemoteObservationFailure;
        return std::unexpected(
            error(operation,
                  code,
                  code == InspectionErrorCode::RemoteContentNotFound
                      ? "remote file content not found"
                      : "failed to download remote content"));
    }
    if (!crypto::decrypt_file(encrypted, plaintext, context.key) ||
        !crypto::content::verify_file(plaintext, logical_hash, row->size)) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteContentInvalid,
                  "remote content failed cryptographic authentication"));
    }
    if (auto installed =
            install_remote_file(plaintext, *destination, operation);
        !installed) {
        return std::unexpected(installed.error());
    }
    return RemoteFileReport{.path = row->path,
                            .destination_path =
                                platform::path::to_utf8(*destination),
                            .logical_hash = logical_hash,
                            .content_id = content_id,
                            .size = row->size};
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
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "failed to authenticate remote Epoch chain"));
    }
    if (operation == InspectionOperation::RemoteEpochs) {
        RemoteEpochsReport report;
        report.epochs.reserve(chain->size());
        for (std::size_t index = 0; index < chain->size(); ++index) {
            report.epochs.push_back(epoch_info(*chain, index));
        }
        return InspectionResponse{.operation = operation,
                                  .payload = std::move(report)};
    }

    const auto& selector = *request.epoch_selector;
    const auto sequence = epoch_sequence(selector);
    const auto selected = std::ranges::find_if(*chain, [&](const auto& epoch) {
        return history::valid_commit_id(selector)
                   ? epoch.reference.epoch_id == selector
                   : sequence && epoch.reference.sequence == *sequence;
    });
    if (selected == chain->end()) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::RemoteEpochNotFound,
                                     "requested remote Epoch does not exist"));
    }
    const auto index = static_cast<std::size_t>(selected - chain->begin());
    return InspectionResponse{
        .operation = operation,
        .payload = RemoteEpochReport{.epoch = epoch_info(*chain, index)}};
}

std::expected<RemoteContentsReport, InspectionError>
inspect_contents(const observation::history::StorageView& observed,
                 InspectionContext& context,
                 InspectionOperation operation,
                 bool audit) {
    std::map<std::string, RemoteContentInfo> inventory;
    const auto add_rows = [&](const Snapshot& tree, bool current) {
        for (const auto& row : tree.rows) {
            if (row.is_directory) {
                continue;
            }
            const auto logical_hash = hash_hex(row.hash);
            const auto content_id =
                crypto::content_identifier(context.key, row.hash);
            auto& content = inventory[content_id];
            if (content.content_id.empty()) {
                content.content_id = content_id;
                content.logical_hash = logical_hash;
                content.size = row.size;
                content.referenced = true;
            } else if (content.logical_hash != logical_hash ||
                       content.size != row.size) {
                return false;
            }
            content.current_tree = content.current_tree || current;
            content.paths.push_back(row.path.empty() ? "/" : row.path);
        }
        return true;
    };
    if (!add_rows(observed.effective_tree, true)) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "logical content inventory is inconsistent"));
    }
    for (const auto& commit : observed.reachable_commits) {
        if (!add_rows(commit.commit.tree, false)) {
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::RemoteObservationFailure,
                      "history has inconsistent content metadata"));
        }
    }
    for (const auto& content_id : observed.content_object_identifiers) {
        auto& content = inventory[content_id];
        content.content_id = content_id;
        content.physically_present = true;
    }

    std::size_t audit_index = 0;
    for (auto& [unused, content] : inventory) {
        std::ranges::sort(content.paths);
        const auto unique = std::ranges::unique(content.paths);
        content.paths.erase(unique.begin(), unique.end());
        content.state = !content.physically_present
                            ? RemoteContentState::Missing
                        : content.referenced ? RemoteContentState::Present
                                             : RemoteContentState::Orphan;
        if (!audit || !content.physically_present) {
            continue;
        }

        auto audited = history_storage::audit_content_object(
            context.storage,
            context.key,
            content.content_id,
            content.referenced
                ? std::optional<std::string_view>{content.logical_hash}
                : std::nullopt,
            content.referenced ? std::optional<std::uint64_t>{content.size}
                               : std::nullopt,
            context.workspace->root,
            audit_index++);
        if (!audited) {
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::RemoteObservationFailure,
                      "failed to download object during audit"));
        }
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
    auto listed = list_remote_identifiers(context.storage, true, "objects");
    if (!listed) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  listed.error()));
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
    } else if (id.starts_with(layout.writers_prefix)) {
        result.category = RemoteObjectCategory::Writer;
        result.structurally_valid =
            history_storage::valid_writer_identifier(layout, id);
        result.relation = "blocks maintenance while present";
    } else if (id.starts_with(layout.probes_prefix)) {
        result.category = RemoteObjectCategory::Protocol;
        result.structurally_valid = true;
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
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  std::string{message}));
    }
    return std::move(*inventory);
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
    using Source = history_storage::ReachabilityMarkerState;
    switch (state) {
        case Source::InvalidPath:
            return RemoteMarkerState::InvalidPath;
        case Source::Missing:
            return RemoteMarkerState::Missing;
        case Source::InvalidMarker:
            return RemoteMarkerState::InvalidMarker;
        case Source::MissingCommit:
            return RemoteMarkerState::MissingCommit;
        case Source::InvalidCiphertext:
            return RemoteMarkerState::InvalidCiphertext;
        case Source::InvalidCommit:
            return RemoteMarkerState::InvalidCommit;
        case Source::Valid:
            return ancestral ? RemoteMarkerState::Ancestral
                             : RemoteMarkerState::LogicalHead;
    }
    return RemoteMarkerState::InvalidMarker;
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
    report.barrier_present =
        std::ranges::find(identifiers, layout.barrier_identifier) !=
        identifiers.end();
    if (report.barrier_present) {
        report.barrier_identifier = layout.barrier_identifier;
    }
    for (const auto& identifier : identifiers) {
        if (identifier.starts_with(layout.writers_prefix)) {
            const auto state =
                history_storage::valid_writer_identifier(layout, identifier)
                    ? RemoteWriterState::Indeterminate
                    : RemoteWriterState::Invalid;
            report.protocol_consistent &= state != RemoteWriterState::Invalid;
            report.writers.push_back(
                RemoteWriterInfo{.identifier = identifier, .state = state});
        } else if (identifier.starts_with(layout.gc_prefix) &&
                   identifier != layout.barrier_identifier &&
                   !identifier.starts_with(layout.probes_prefix)) {
            report.protocol_consistent = false;
        }
    }
    report.maintenance_blocked =
        report.barrier_present || !report.writers.empty();
    return report;
}

std::expected<RemoteHealthReport, InspectionError>
make_health_report(InspectionContext& context,
                   InspectionOperation operation,
                   const std::vector<std::string>& identifiers) {
    auto epochs = history_storage::epoch::load_chain(
        context.storage, context.key, context.workspace->root, identifiers);
    if (!epochs) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "failed to authenticate Epoch continuity"));
    }
    auto history_inventory = unwrap_inventory(
        history_storage::inventory_reachability(context.storage,
                                                context.key,
                                                identifiers,
                                                *epochs,
                                                context.workspace->root),
        operation,
        "failed to authenticate physical history inventory");
    if (!history_inventory) {
        return std::unexpected(history_inventory.error());
    }
    auto content_inventory =
        unwrap_inventory(history_storage::inventory_content_reachability(
                             context.storage,
                             context.key,
                             identifiers,
                             *history_inventory,
                             context.workspace->root),
                         operation,
                         "failed to audit remote content reachability");
    if (!content_inventory) {
        return std::unexpected(content_inventory.error());
    }
    const auto markers = make_markers_report(*history_inventory);
    const auto objects = make_objects_report(context.layout, identifiers);
    const auto writers = make_writers_report(context.layout, identifiers);
    const auto orphans = make_orphans_report(
        context.layout, *history_inventory, *content_inventory);

    RemoteHealthReport report{
        .marker_count = markers.markers.size(),
        .reachable_commit_count = history_inventory->reachable_commits.size(),
        .orphan_count = static_cast<std::size_t>(
            std::ranges::count_if(orphans.objects,
                                  [](const auto& item) {
                                      return item.removal_candidate;
                                  })),
        .missing_content_count = content_inventory->missing_content_ids.size(),
        .writer_count = writers.writers.size(),
        .unknown_object_count = objects.unknown_count,
    };
    report.invalid_content_count =
        static_cast<std::size_t>(std::ranges::count_if(
            content_inventory->contents, [](const auto& content) {
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
    add_count_reason(history_inventory->missing_parent_ids.size(),
                     "missing commit parents");
    add_count_reason(history_inventory->invalid_parent_ids.size(),
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
    const auto respond = [&](auto payload) {
        return InspectionResponse{.operation = operation,
                                  .payload = std::move(payload)};
    };
    if (operation == InspectionOperation::RemoteMarkers) {
        auto inventory = unwrap_inventory(
            history_storage::inventory_reachability(
                context.storage, context.key, context.workspace->root),
            operation,
            "failed to authenticate physical history inventory");
        if (!inventory) {
            return std::unexpected(inventory.error());
        }
        return respond(make_markers_report(*inventory));
    }
    auto identifiers = physical_objects(context, operation);
    if (!identifiers) {
        return std::unexpected(identifiers.error());
    }
    if (operation == InspectionOperation::RemoteOrphans) {
        auto history_inventory = unwrap_inventory(
            history_storage::inventory_reachability(context.storage,
                                                    context.key,
                                                    *identifiers,
                                                    context.workspace->root),
            operation,
            "failed to authenticate physical history inventory");
        if (!history_inventory) {
            return std::unexpected(history_inventory.error());
        }
        auto contents =
            unwrap_inventory(history_storage::inventory_content_reachability(
                                 context.storage,
                                 context.key,
                                 *identifiers,
                                 *history_inventory,
                                 context.workspace->root),
                             operation,
                             "failed to audit remote content reachability");
        if (!contents) {
            return std::unexpected(contents.error());
        }
        return respond(
            make_orphans_report(context.layout, *history_inventory, *contents));
    }
    if (operation == InspectionOperation::RemoteObjects) {
        return respond(
            make_objects_report(context.layout, std::move(*identifiers)));
    }
    if (operation == InspectionOperation::RemoteWriters) {
        return respond(make_writers_report(context.layout, *identifiers));
    }
    auto health = make_health_report(context, operation, *identifiers);
    if (!health) {
        return std::unexpected(health.error());
    }
    return respond(std::move(*health));
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
        return std::unexpected(error(operation,
                                     InspectionErrorCode::RemoteCommitNotFound,
                                     "commit is not reachable in current "
                                     "remote history"));
    }
    if (!valid_commit_snapshot(*selected)) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "remote commit does not have a valid tree"));
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
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "failed to authenticate physical commit variants"));
    }

    RemoteCommitReport report{.commit = commit_info(*selected, observed)};
    report.variants.reserve(inspected->size());
    for (const auto& variant : *inspected) {
        const auto state =
            variant.state == history_storage::PhysicalCommitVariantState::Valid
                ? RemoteCommitVariantState::Valid
            : variant.state ==
                    history_storage::PhysicalCommitVariantState::InvalidCommit
                ? RemoteCommitVariantState::InvalidCommit
                : RemoteCommitVariantState::InvalidCiphertext;
        report.variants.push_back(RemoteCommitVariantInfo{
            .ciphertext_id = variant.reference.ciphertext_id,
            .object_identifier = variant.identifier,
            .state = state,
        });
    }
    return report;
}

std::expected<InspectionResponse, InspectionError>
run_inspection(InspectionInput& input, InspectionContext& context) {
    const auto operation = input.request.operation;
    const auto& req = input.request;
    const auto invalid = [&](std::string msg) {
        return std::unexpected(error(
            operation, InspectionErrorCode::InvalidRequest, std::move(msg)));
    };
    const bool allowed_selectors =
        (!req.head_commit_id || operation == InspectionOperation::RemoteTree) &&
        (!req.logical_path || operation == InspectionOperation::RemoteStat ||
         operation == InspectionOperation::RemoteGet) &&
        (!req.commit_id || operation == InspectionOperation::RemoteCommit) &&
        (!req.destination_path ||
         operation == InspectionOperation::RemoteGet) &&
        (!req.epoch_selector ||
         operation == InspectionOperation::RemoteEpoch) &&
        (!req.content_id || operation == InspectionOperation::RemoteContent);
    if (!allowed_selectors) {
        return invalid(
            "selector does not belong to requested inspection operation");
    }
    switch (operation) {
        case InspectionOperation::RemoteHeads:
        case InspectionOperation::RemoteCommits:
        case InspectionOperation::RemoteSummary:
        case InspectionOperation::RemoteEpochs:
        case InspectionOperation::RemoteContents:
        case InspectionOperation::RemoteContentsAudit:
        case InspectionOperation::RemoteMarkers:
        case InspectionOperation::RemoteObjects:
        case InspectionOperation::RemoteOrphans:
        case InspectionOperation::RemoteWriters:
        case InspectionOperation::RemoteHealth:
        case InspectionOperation::RemoteTree:
            break;
        case InspectionOperation::RemoteStat:
            if (!req.logical_path || !valid_logical_path(*req.logical_path)) {
                return invalid("requested logical path is invalid");
            }
            break;
        case InspectionOperation::RemoteGet:
            if (!req.logical_path || !valid_logical_path(*req.logical_path) ||
                *req.logical_path == "/" || !req.destination_path ||
                req.destination_path->empty()) {
                return invalid("remote path or destination is invalid");
            }
            break;
        case InspectionOperation::RemoteCommit:
            if (!req.commit_id || !history::valid_commit_id(*req.commit_id)) {
                return invalid("requested commit ID is invalid");
            }
            break;
        case InspectionOperation::RemoteContent:
            if (!req.content_id || !history::valid_commit_id(*req.content_id)) {
                return invalid("requested content ID is invalid");
            }
            break;
        case InspectionOperation::RemoteEpoch:
            if (!req.epoch_selector ||
                (!history::valid_commit_id(*req.epoch_selector) &&
                 !epoch_sequence(*req.epoch_selector))) {
                return invalid("requested Epoch ID or sequence is invalid");
            }
            break;
        default:
            return std::unexpected(error(operation,
                                         InspectionErrorCode::RuntimeFailure,
                                         "unknown inspection operation"));
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

    auto key =
        resolve_key(input.credentials, context.runtime, context.key, operation);
    if (!key) {
        return std::unexpected(key.error());
    }
    context.layout = history_storage::derive_remote_layout(context.key);

    context.hints =
        make_observation_hints(context.runtime, operation, context.layout);

    auto opened = transport::open_transport(context.runtime.storage_location,
                                            context.runtime.local_dir);
    if (!opened) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::RuntimeFailure,
                                     "failed to open remote storage"));
    }
    context.storage = std::move(*opened);

    auto workspace = platform::create_workspace("remote-inspection");
    if (!workspace) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "failed to prepare remote observation"));
    }
    context.workspace = std::move(*workspace);

    const auto respond = [&](auto expected_payload)
        -> std::expected<InspectionResponse, InspectionError> {
        if (!expected_payload) {
            return std::unexpected(expected_payload.error());
        }
        return InspectionResponse{.operation = operation,
                                  .payload = std::move(*expected_payload)};
    };

    if (operation == InspectionOperation::RemoteEpochs ||
        operation == InspectionOperation::RemoteEpoch) {
        return inspect_epochs(input.request, context, operation);
    }
    if (operation == InspectionOperation::RemoteMarkers ||
        operation == InspectionOperation::RemoteObjects ||
        operation == InspectionOperation::RemoteOrphans ||
        operation == InspectionOperation::RemoteWriters ||
        operation == InspectionOperation::RemoteHealth) {
        return inspect_physical(context, operation);
    }

    const bool audit_content_objects =
        operation == InspectionOperation::RemoteSummary ||
        operation == InspectionOperation::RemoteContents ||
        operation == InspectionOperation::RemoteContentsAudit ||
        operation == InspectionOperation::RemoteContent;
    auto observed = observation::history::observe(
        context.storage,
        context.key,
        context.workspace->root,
        audit_content_objects,
        context.hints.frontier ? &*context.hints.frontier : nullptr,
        context.hints.trusted_marker_identifiers,
        requires_complete_history(operation));
    if (!observed) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "failed to observe remote history"));
    }

    if (operation == InspectionOperation::RemoteContents ||
        operation == InspectionOperation::RemoteContentsAudit ||
        operation == InspectionOperation::RemoteContent) {
        auto contents = inspect_contents(
            *observed,
            context,
            operation,
            operation == InspectionOperation::RemoteContentsAudit);
        if (!contents || operation != InspectionOperation::RemoteContent) {
            return respond(std::move(contents));
        }
        const auto selected = std::ranges::find(contents->contents,
                                                *input.request.content_id,
                                                &RemoteContentInfo::content_id);
        if (selected == contents->contents.end()) {
            return std::unexpected(error(
                operation,
                InspectionErrorCode::RemoteContentNotFound,
                "requested content ID does not exist in remote inventory"));
        }
        return InspectionResponse{
            .operation = operation,
            .payload = RemoteContentReport{.content = std::move(*selected)}};
    }

    if (operation == InspectionOperation::RemoteSummary) {
        auto writers = history_storage::maintenance_protocol::active_writers(
            context.storage, context.layout);
        if (!writers) {
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::RemoteObservationFailure,
                      "failed to observe remote writers"));
        }
        return InspectionResponse{
            .operation = operation,
            .payload = RemoteSummaryReport{
                .history_present = observed->history_present,
                .observed_height = observed->observed_height,
                .reachable_commit_count = observed->reachable_commit_ids.size(),
                .logical_head_count = observed->logical_heads.size(),
                .has_conflicts = observed->has_conflicts,
                .missing_content_count = observed->missing_content_count,
                .orphan_content_count = observed->orphan_content_count,
                .active_writer_count = writers->size(),
            }};
    }

    if (operation == InspectionOperation::RemoteHeads ||
        operation == InspectionOperation::RemoteTree) {
        auto heads = make_head_infos(*observed, operation);
        if (!heads) {
            return std::unexpected(heads.error());
        }
        if (operation == InspectionOperation::RemoteTree) {
            return respond(
                make_tree_report(input.request, *observed, *heads, operation));
        }
        return InspectionResponse{
            .operation = operation,
            .payload = RemoteHeadsReport{
                .history_present = observed->history_present,
                .observed_height = observed->observed_height,
                .physical_marker_count =
                    observed->marked_head_identifiers.size(),
                .ancestral_marker_count =
                    observed->ancestral_marked_heads.size(),
                .heads = std::move(*heads),
            }};
    }

    if (operation == InspectionOperation::RemoteStat) {
        return respond(make_stat_report(input.request, *observed, operation));
    }
    if (operation == InspectionOperation::RemoteCommit) {
        return respond(
            make_commit_report(input.request, *observed, context, operation));
    }
    if (operation == InspectionOperation::RemoteGet) {
        return respond(
            download_remote_file(input.request, *observed, context, operation));
    }
    return respond(make_commits_report(*observed, operation));
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
    std::expected<InventoryAuditReport, std::string> result =
        std::unexpected("remote inventory audit failed");
    try {
        do {
            const auto identifiers =
                list_remote_identifiers(storage, false, "inventory");
            if (!identifiers) {
                result = std::unexpected(identifiers.error());
                break;
            }
            const auto layout = history_storage::derive_remote_layout(key);
            const auto writers = make_writers_report(layout, *identifiers);
            if (writers.maintenance_blocked || !writers.protocol_consistent) {
                result =
                    std::unexpected("remote inventory is inconclusive while "
                                    "maintenance or a writer is active");
                break;
            }
            auto epochs = history_storage::epoch::load_chain(
                storage, key, workspace->root, *identifiers);
            if (!epochs) {
                result = std::unexpected(
                    "failed to authenticate remote Epoch history");
                break;
            }
            auto history_inventory = history_storage::inventory_reachability(
                storage, key, *identifiers, *epochs, workspace->root);
            if (!history_inventory) {
                result = std::unexpected(
                    "failed to authenticate remote history inventory");
                break;
            }
            if (history_inventory->logical_heads.empty() ||
                !history_inventory->missing_parent_ids.empty() ||
                !history_inventory->invalid_parent_ids.empty()) {
                result = std::unexpected(
                    "remote history is incomplete; inventory is inconclusive");
                break;
            }
            auto content_inventory =
                history_storage::inventory_content_reachability(
                    storage,
                    key,
                    *identifiers,
                    *history_inventory,
                    workspace->root);
            if (!content_inventory) {
                result = std::unexpected(
                    "failed to classify remote content reachability");
                break;
            }
            const auto objects = make_objects_report(layout, *identifiers);
            const auto unchanged =
                list_remote_identifiers(storage, false, "inventory");
            if (!unchanged) {
                result = std::unexpected(unchanged.error());
                break;
            }
            if (*identifiers != *unchanged) {
                result =
                    std::unexpected("remote inventory changed during audit; "
                                    "results are inconclusive");
                break;
            }
            if (content_inventory->missing_content_ids.size() >
                content_inventory->reachable_content_ids.size()) {
                result = std::unexpected(
                    "remote content inventory is internally inconsistent");
                break;
            }
            result = InventoryAuditReport{
                .referenced_content =
                    content_inventory->reachable_content_ids.size(),
                .present_content =
                    content_inventory->reachable_content_ids.size() -
                    content_inventory->missing_content_ids.size(),
                .missing_content =
                    content_inventory->missing_content_ids.size(),
                .orphan_content = content_inventory->orphan_content_ids.size(),
                .unknown_objects = objects.unknown_count,
            };
        } while (false);
    } catch (...) {
        result = std::unexpected("exception during remote inventory audit");
    }
    platform::cleanup_workspace(*workspace);
    return result;
}

std::expected<InspectionResponse, InspectionError>
inspect(InspectionInput input) {
    platform::perf_trace::reset();
    const auto total_trace = platform::perf_trace::begin();
    InspectionContext context;
    std::expected<InspectionResponse, InspectionError> result =
        std::unexpected(error(input.request.operation,
                              InspectionErrorCode::RuntimeFailure,
                              "remote inspection failure"));
    try {
        result = run_inspection(input, context);
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

} // namespace kasumi::application
