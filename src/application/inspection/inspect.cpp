#include "application/inspection/inspect.hpp"

#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/detail.hpp"
#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/observation/history.hpp"
#include "core/wire.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/durability.hpp"
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
#include <chrono>
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

struct InspectionHistoryCache {
    std::string anchor_id;
    std::optional<history_storage::epoch::Reference> epoch;
    std::vector<history::LoadedCommit> commits;
};

struct InspectionObservationHints {
    std::optional<history_storage::KnownHistoryFrontier> frontier;
    std::vector<std::string> trusted_marker_identifiers;
    std::optional<InspectionHistoryCache> history_cache;
};

struct InspectionContext {
    runtime::RuntimeData runtime;
    runtime::vault::KeyBytes key{};
    transport::Transport storage{};
    std::optional<platform::Workspace> workspace;
    InspectionObservationHints hints;
};

constexpr std::array<std::byte, 8> history_cache_magic{std::byte{'K'},
                                                       std::byte{'S'},
                                                       std::byte{'H'},
                                                       std::byte{'C'},
                                                       std::byte{'A'},
                                                       std::byte{'C'},
                                                       std::byte{'H'},
                                                       std::byte{'E'}};
constexpr std::uint32_t history_cache_version = 1;
constexpr std::uint64_t maximum_history_cache_size = 256ULL * 1024ULL * 1024ULL;
constexpr std::string_view history_cache_name = "inspection-history-v1.cache";
constexpr std::size_t history_cache_tag_size = 64;
constexpr std::size_t history_cache_trailer_size =
    sizeof(std::uint32_t) + history_cache_tag_size;

bool requires_complete_history(InspectionOperation operation) noexcept {
    return operation == InspectionOperation::RemoteCommits ||
           operation == InspectionOperation::RemoteSummary ||
           operation == InspectionOperation::RemoteCommit ||
           operation == InspectionOperation::RemoteContents ||
           operation == InspectionOperation::RemoteContentsAudit ||
           operation == InspectionOperation::RemoteContent;
}

std::filesystem::path
history_cache_path(const runtime::RuntimeData& runtime_data) {
    return runtime_data.database_path.parent_path() / history_cache_name;
}

bool same_commit(const history::Commit& left, const history::Commit& right) {
    const auto left_bytes = history::serialize(left);
    const auto right_bytes = history::serialize(right);
    return left_bytes && right_bytes && *left_bytes == *right_bytes;
}

bool cache_graph_is_complete(const InspectionHistoryCache& cache) {
    if (cache.commits.empty() || !history::valid_commit_id(cache.anchor_id)) {
        return false;
    }
    std::unordered_map<std::string_view, const history::LoadedCommit*> commits;
    commits.reserve(cache.commits.size());
    for (const auto& commit : cache.commits) {
        if (!commits.emplace(commit.id, &commit).second) {
            return false;
        }
    }
    if (!commits.contains(cache.anchor_id)) {
        return false;
    }
    std::unordered_set<std::string_view> visited;
    std::vector<std::string_view> pending{cache.anchor_id};
    while (!pending.empty()) {
        const auto current = pending.back();
        pending.pop_back();
        if (!visited.insert(current).second) {
            continue;
        }
        const auto found = commits.find(current);
        if (found == commits.end()) {
            return false;
        }
        for (const auto& parent : found->second->commit.parents) {
            pending.push_back(parent);
        }
    }
    if (visited.size() != commits.size()) {
        return false;
    }
    const std::array marked_heads{cache.anchor_id};
    const auto resolved =
        history::resolve_authenticated(cache.commits, marked_heads);
    return resolved && resolved->heads == std::vector{cache.anchor_id};
}

std::optional<InspectionHistoryCache>
load_history_cache(const runtime::RuntimeData& runtime_data,
                   std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    try {
        std::error_code filesystem_error;
        if (!std::filesystem::is_regular_file(runtime_data.database_path,
                                              filesystem_error) ||
            filesystem_error) {
            return std::nullopt;
        }
        const auto path = history_cache_path(runtime_data);
        const auto status =
            std::filesystem::symlink_status(path, filesystem_error);
        if (filesystem_error ||
            status.type() != std::filesystem::file_type::regular) {
            return std::nullopt;
        }
        const auto size = std::filesystem::file_size(path, filesystem_error);
        if (filesystem_error || size > maximum_history_cache_size ||
            size > static_cast<std::uint64_t>(
                       std::numeric_limits<std::streamsize>::max())) {
            return std::nullopt;
        }
        std::string bytes(static_cast<std::size_t>(size), '\0');
        std::ifstream input(path, std::ios::binary);
        if (!input ||
            (!bytes.empty() &&
             !input.read(bytes.data(), static_cast<std::streamsize>(size)))) {
            return std::nullopt;
        }
        if (bytes.size() < history_cache_trailer_size) {
            return std::nullopt;
        }
        const auto signed_size = bytes.size() - history_cache_trailer_size;
        wire::Reader trailer{std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(bytes.data() + signed_size),
            history_cache_trailer_size}};
        const auto tag = wire::read_string(trailer, history_cache_tag_size);
        const auto signed_bytes = std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t*>(bytes.data()), signed_size};
        if (!tag || !trailer.data.empty() ||
            crypto::commit_identifier(key, signed_bytes) != *tag) {
            return std::nullopt;
        }
        wire::Reader reader{std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(bytes.data()), signed_size}};
        const auto magic = wire::read_array<history_cache_magic.size()>(reader);
        const auto version = wire::read<std::uint32_t>(reader);
        const auto anchor_id = wire::read_string(reader, 64);
        const auto epoch_sequence = wire::read<std::uint64_t>(reader);
        const auto epoch_id = wire::read_string(reader, 64);
        const auto count = wire::read<std::uint32_t>(reader);
        if (!magic || *magic != history_cache_magic || !version ||
            *version != history_cache_version || !anchor_id ||
            !epoch_sequence || !epoch_id || !count ||
            *count > history::maximum_loaded_commit_count ||
            (!epoch_id->empty() && !history::valid_commit_id(*epoch_id)) ||
            (epoch_id->empty() && *epoch_sequence != 0)) {
            return std::nullopt;
        }

        InspectionHistoryCache cache{.anchor_id = std::move(*anchor_id)};
        if (!epoch_id->empty()) {
            cache.epoch = history_storage::epoch::Reference{
                .sequence = *epoch_sequence, .epoch_id = std::move(*epoch_id)};
        }
        cache.commits.reserve(*count);
        for (std::uint32_t index = 0; index < *count; ++index) {
            auto id = wire::read_string(reader, 64);
            auto encoded_size = wire::read<std::uint64_t>(reader);
            if (!id || !history::valid_commit_id(*id) || !encoded_size ||
                *encoded_size > history::maximum_commit_plaintext_size) {
                return std::nullopt;
            }
            auto encoded = wire::read_bytes(
                reader, static_cast<std::size_t>(*encoded_size));
            if (!encoded) {
                return std::nullopt;
            }
            const auto commit_bytes = std::span<const std::uint8_t>{
                reinterpret_cast<const std::uint8_t*>(encoded->data()),
                encoded->size()};
            auto commit = history::deserialize(commit_bytes);
            if (!commit) {
                return std::nullopt;
            }
            auto canonical = history::serialize(*commit);
            if (!canonical || !std::ranges::equal(*canonical, commit_bytes)) {
                return std::nullopt;
            }
            cache.commits.push_back(history::LoadedCommit{
                .id = std::move(*id), .commit = std::move(*commit)});
        }
        if (!reader.data.empty() || !cache_graph_is_complete(cache)) {
            return std::nullopt;
        }
        return cache;
    } catch (...) {
        return std::nullopt;
    }
}

bool save_history_cache(const runtime::RuntimeData& runtime_data,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const observation::history::StorageView& observed) {
    try {
        std::error_code filesystem_error;
        // ponytail: current frontier supports a single head; concurrency uses cold
        // observation until there is a measured gain for a multi-head cache.
        if (observed.logical_heads.size() != 1 ||
            !std::filesystem::is_regular_file(runtime_data.database_path,
                                              filesystem_error) ||
            filesystem_error ||
            observed.reachable_commits.size() >
                history::maximum_loaded_commit_count) {
            return false;
        }
        auto commits = observed.reachable_commits;
        std::ranges::sort(commits, {}, &history::LoadedCommit::id);
        const InspectionHistoryCache cache{
            .anchor_id = observed.logical_heads.front(),
            .epoch = observed.epoch
                         ? std::optional{observed.epoch->reference}
                         : std::optional<history_storage::epoch::Reference>{},
            .commits = commits,
        };
        if (!cache_graph_is_complete(cache)) {
            return false;
        }
        wire::Writer writer;
        wire::write_array(writer, history_cache_magic);
        wire::write(writer, history_cache_version);
        wire::write_string(writer, observed.logical_heads.front());
        wire::write(writer,
                    observed.epoch ? observed.epoch->reference.sequence : 0);
        wire::write_string(writer,
                           observed.epoch ? observed.epoch->reference.epoch_id
                                          : std::string_view{});
        wire::write(writer, static_cast<std::uint32_t>(commits.size()));
        for (const auto& loaded : commits) {
            auto encoded = history::serialize(loaded.commit);
            if (!encoded || !history::valid_commit_id(loaded.id)) {
                return false;
            }
            wire::write_string(writer, loaded.id);
            wire::write(writer, static_cast<std::uint64_t>(encoded->size()));
            wire::write_bytes(writer, std::as_bytes(std::span{*encoded}));
            if (writer.buffer.size() > maximum_history_cache_size) {
                return false;
            }
        }
        const auto signed_bytes = std::span<const std::uint8_t>{
            reinterpret_cast<const std::uint8_t*>(writer.buffer.data()),
            writer.buffer.size()};
        wire::write_string(writer,
                           crypto::commit_identifier(key, signed_bytes));
        if (writer.buffer.size() > maximum_history_cache_size) {
            return false;
        }
        const auto bytes = std::string_view{
            reinterpret_cast<const char*>(writer.buffer.data()),
            writer.buffer.size()};
        return platform::private_storage::write_atomically(
                   history_cache_path(runtime_data), bytes)
            .has_value();
    } catch (...) {
        return false;
    }
}

bool merge_history_cache(observation::history::StorageView& observed,
                         const InspectionHistoryCache& cache) {
    try {
        const auto observed_epoch =
            observed.epoch ? std::optional{observed.epoch->reference}
                           : std::optional<history_storage::epoch::Reference>{};
        if (observed_epoch != cache.epoch) {
            return false;
        }
        std::map<std::string, history::LoadedCommit> merged;
        for (const auto& loaded : observed.reachable_commits) {
            merged.emplace(loaded.id, loaded);
        }
        for (const auto& cached : cache.commits) {
            const auto found = merged.find(cached.id);
            if (found == merged.end()) {
                merged.emplace(cached.id, cached);
                continue;
            }
            if (same_commit(found->second.commit, cached.commit)) {
                continue;
            }
            if (cached.id != cache.anchor_id ||
                found->second.commit.height != cached.commit.height ||
                found->second.commit.tree != cached.commit.tree) {
                return false;
            }
            found->second = cached;
        }
        if (merged.size() > history::maximum_loaded_commit_count) {
            return false;
        }
        std::vector<history::LoadedCommit> commits;
        commits.reserve(merged.size());
        for (auto& [unused, commit] : merged) {
            static_cast<void>(unused);
            commits.push_back(std::move(commit));
        }
        const auto resolved =
            history::resolve_authenticated(commits, observed.marked_heads);
        if (!resolved || resolved->tree != observed.effective_tree ||
            resolved->height != observed.observed_height ||
            resolved->heads != observed.logical_heads ||
            resolved->has_conflicts != observed.has_conflicts) {
            return false;
        }
        observed.reachable_commits = std::move(commits);
        observed.reachable_commit_ids.clear();
        observed.reachable_commit_ids.reserve(
            observed.reachable_commits.size());
        for (const auto& commit : observed.reachable_commits) {
            observed.reachable_commit_ids.push_back(commit.id);
        }
        return true;
    } catch (...) {
        return false;
    }
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
    InspectionErrorCode code = InspectionErrorCode::RuntimeFailure;
    switch (source.code) {
        case runtime::ErrorCode::InvalidProfileName:
            code = InspectionErrorCode::InvalidProfile;
            break;
        case runtime::ErrorCode::ProfileNotFound:
            code = InspectionErrorCode::ProfileNotFound;
            break;
        default:
            break;
    }
    return error(operation, code, source.detail);
}

std::expected<bool, InspectionError>
key_file_present(const std::filesystem::path& path,
                 InspectionOperation operation) {
    std::error_code filesystem_error;
    const auto status = std::filesystem::symlink_status(path, filesystem_error);
    if (filesystem_error &&
        filesystem_error != std::errc::no_such_file_or_directory) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::RuntimeFailure,
                                     "não foi possível verificar a chave "
                                     "persistida"));
    }
    return status.type() != std::filesystem::file_type::not_found;
}

std::expected<void, InspectionError>
resolve_key(const Credentials& credentials,
            const runtime::RuntimeData& runtime_data,
            runtime::vault::KeyBytes& output,
            InspectionOperation operation) {
    auto present = key_file_present(runtime_data.key_path, operation);
    if (!present) {
        return std::unexpected(present.error());
    }

    if (std::holds_alternative<NoCredentials>(credentials)) {
        if (!*present) {
            return std::unexpected(error(
                operation,
                InspectionErrorCode::CredentialsRequired,
                "credenciais são necessárias para inspecionar o histórico "
                "remoto"));
        }
        auto stored = runtime::vault::read_only(runtime_data.key_path);
        if (!stored) {
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::CredentialFailure,
                      "não foi possível ler a chave persistida do perfil"));
        }
        output = *stored;
        crypto::secure_memory::wipe(stored->data(), stored->size());
        return {};
    }

    const auto& master_key = std::get<MasterKeyHex>(credentials);
    auto resolved = runtime::vault::decode_hex(master_key.value);
    if (!resolved) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::CredentialFailure,
                                     resolved.error().detail));
    }

    if (*present) {
        auto stored = runtime::vault::read_only(runtime_data.key_path);
        if (!stored) {
            crypto::secure_memory::wipe(resolved->data(), resolved->size());
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::CredentialFailure,
                      "não foi possível ler a chave persistida do perfil"));
        }
        const bool matches = *stored == *resolved;
        crypto::secure_memory::wipe(stored->data(), stored->size());
        if (!matches) {
            crypto::secure_memory::wipe(resolved->data(), resolved->size());
            return std::unexpected(error(operation,
                                         InspectionErrorCode::CredentialFailure,
                                         "a credencial não corresponde ao "
                                         "perfil"));
        }
    }

    output = *resolved;
    crypto::secure_memory::wipe(resolved->data(), resolved->size());
    return {};
}

InspectionObservationHints
make_observation_hints(const runtime::RuntimeData& runtime_data,
                       InspectionOperation operation,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    const auto state_trace = platform::perf_trace::begin();
    InspectionObservationHints hints;
    auto persisted = state_storage::load_state(runtime_data.database_path);
    if (!persisted || !*persisted) {
        platform::perf_trace::count("inspection frontier unavailable");
        platform::perf_trace::finish("inspection state load", state_trace);
        return hints;
    }

    platform::perf_trace::count("inspection persisted state available");
    auto& state = **persisted;
    if (requires_complete_history(operation)) {
        auto cache = load_history_cache(runtime_data, key);
        if (cache) {
            const auto anchor = std::ranges::find(
                cache->commits, cache->anchor_id, &history::LoadedCommit::id);
            if (anchor != cache->commits.end()) {
                hints.frontier.emplace();
                hints.frontier->anchors.push_back(
                    history_storage::KnownHistoryAnchor{
                        .commit_id = anchor->id,
                        .height = anchor->commit.height,
                        .tree = anchor->commit.tree,
                    });
                hints.frontier->accepted_epoch = cache->epoch;
                hints.history_cache = std::move(*cache);
                platform::perf_trace::count("inspection history cache used");
                platform::perf_trace::count("inspection frontier used");
            }
        }
        if (!hints.frontier) {
            platform::perf_trace::count("inspection frontier unavailable");
        }
    } else if (operation == InspectionOperation::RemoteHeads ||
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
        platform::perf_trace::count("inspection frontier used");
    } else {
        platform::perf_trace::count("inspection frontier unavailable");
    }

    if (!state.ciphertext_id.empty()) {
        const history_storage::HeadReference reference{
            .commit_id = state.commit_id,
            .ciphertext_id = state.ciphertext_id,
        };
        if (history_storage::valid(reference)) {
            hints.trusted_marker_identifiers.push_back(
                history_storage::marker_object(reference));
            platform::perf_trace::count("inspection trusted marker used");
        }
    }
    platform::perf_trace::finish("inspection state load", state_trace);
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
                      "o histórico remoto contém um commit duplicado"));
        }
    }
    platform::perf_trace::count("inspection commit index builds");
    platform::perf_trace::count("inspection commit index entries",
                                result.size());
    return result;
}

std::expected<RemoteHeadInfo, InspectionError>
make_head_info(std::string_view id,
               const ObservedCommitIndex& commits,
               InspectionOperation operation) {
    const auto observed = commits.find(id);
    if (observed == commits.end() ||
        observed->second->commit.tree.rows.empty() ||
        !kasumi::valid_snapshot(observed->second->commit.tree, false)) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "a head lógica não possui um commit observado válido"));
    }
    const auto* match = observed->second;

    const auto& tree = match->commit.tree;
    RemoteHeadInfo result{.commit_id = match->id,
                          .height = match->commit.height,
                          .created_at = match->commit.created_at,
                          .parent_ids = match->commit.parents,
                          .root_hash = hash_hex(tree.rows.front().hash),
                          .total_bytes = tree.rows.front().size};
    for (const auto& row : tree.rows) {
        if (row.is_directory) {
            if (!row.path.empty()) {
                ++result.directory_count;
            }
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
        if (left.height != right.height) {
            return left.height > right.height;
        }
        return left.commit_id < right.commit_id;
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
            return std::unexpected(error(
                operation,
                InspectionErrorCode::RemoteHeadNotFound,
                "a head solicitada não está entre as heads lógicas atuais"));
        }
        return report;
    }

    if (heads.empty()) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "o histórico remoto não possui head lógica observada"));
    }

    std::string selected_id;
    if (request.head_commit_id) {
        const auto selected =
            std::ranges::find(observed.logical_heads, *request.head_commit_id);
        if (selected == observed.logical_heads.end()) {
            return std::unexpected(error(
                operation,
                InspectionErrorCode::RemoteHeadNotFound,
                "a head solicitada não está entre as heads lógicas atuais",
                head_ids(heads)));
        }
        selected_id = *selected;
    } else {
        if (heads.size() > 1) {
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::HeadSelectionRequired,
                      "O histórico remoto possui múltiplas heads lógicas.",
                      head_ids(heads)));
        }
        selected_id = heads.front().commit_id;
    }

    const auto selected = std::ranges::find(
        observed.reachable_commits, selected_id, &history::LoadedCommit::id);
    if (selected == observed.reachable_commits.end() ||
        selected->commit.tree.rows.empty() ||
        !valid_snapshot(selected->commit.tree, false)) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "a head lógica não possui um commit observado válido"));
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

std::expected<RemoteCommitsReport, InspectionError>
make_commits_report(const observation::history::StorageView& observed,
                    InspectionOperation operation) {
    RemoteCommitsReport report{.history_present = observed.history_present,
                               .observed_height = observed.observed_height};
    if (!observed.history_present) {
        return report;
    }
    if (observed.reachable_commits.empty()) {
        return std::unexpected(error(
            operation,
            InspectionErrorCode::RemoteObservationFailure,
            "o histórico remoto não possui commits alcançáveis observados"));
    }

    const std::unordered_set<std::string_view> logical_head_ids(
        observed.logical_heads.begin(), observed.logical_heads.end());
    const std::unordered_set<std::string_view> marked_head_ids(
        observed.marked_heads.begin(), observed.marked_heads.end());
    const std::unordered_set<std::string_view> ancestral_marked_head_ids(
        observed.ancestral_marked_heads.begin(),
        observed.ancestral_marked_heads.end());
    platform::perf_trace::count(
        "inspection commit classification index builds");
    platform::perf_trace::count(
        "inspection commit classification index entries",
        logical_head_ids.size() + marked_head_ids.size() +
            ancestral_marked_head_ids.size());

    report.commits.reserve(observed.reachable_commits.size());
    std::vector<std::pair<std::uint64_t, std::string>> logical_heads;
    logical_heads.reserve(observed.logical_heads.size());
    for (const auto& loaded : observed.reachable_commits) {
        const auto& rows = loaded.commit.tree.rows;
        if (rows.empty()) {
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::RemoteObservationFailure,
                      "o histórico remoto contém um commit sem árvore"));
        }

        const bool logical_head = logical_head_ids.contains(loaded.id);
        if (logical_head) {
            logical_heads.emplace_back(loaded.commit.height, loaded.id);
        }
        report.commits.push_back(RemoteCommitInfo{
            .commit_id = loaded.id,
            .height = loaded.commit.height,
            .created_at = loaded.commit.created_at,
            .parent_ids = loaded.commit.parents,
            .logical_head = logical_head,
            .physically_marked = marked_head_ids.contains(loaded.id),
            .ancestral_marked = ancestral_marked_head_ids.contains(loaded.id),
            .root_hash = hash_hex(rows.front().hash),
            .total_bytes = rows.front().size,
            .entry_count = static_cast<std::uint64_t>(rows.size() - 1),
        });
    }

    if (logical_heads.size() != observed.logical_heads.size()) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "a resolução remota referencia uma head não alcançável"));
    }
    std::ranges::sort(logical_heads, [](const auto& left, const auto& right) {
        if (left.first != right.first) {
            return left.first > right.first;
        }
        return left.second < right.second;
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
    if (path == "/") {
        return true;
    }
    if (path.empty() || path.starts_with('/') || path.ends_with('/') ||
        path.contains('\\') || path.contains("//") ||
        (path.size() >= 2 &&
         std::isalpha(static_cast<unsigned char>(path.front())) &&
         path[1] == ':')) {
        return false;
    }
    std::size_t offset = 0;
    while (offset < path.size()) {
        const auto separator = path.find('/', offset);
        const auto component = path.substr(offset, separator - offset);
        if (component == "." || component == "..") {
            return false;
        }
        if (separator == std::string_view::npos) {
            break;
        }
        offset = separator + 1;
    }
    return true;
}

std::int64_t unix_nanoseconds(const NodeRow& row) {
    if (row.is_directory && row.mtime == std::filesystem::file_time_type{}) {
        return 0;
    }
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::clock_cast<std::chrono::system_clock>(row.mtime)
                   .time_since_epoch())
        .count();
}

std::expected<RemoteStatReport, InspectionError>
make_stat_report(const InspectionRequest& request,
                 const observation::history::StorageView& observed,
                 InspectionOperation operation) {
    const auto requested = request.logical_path.value_or("");
    if (!valid_logical_path(requested)) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::InvalidRequest,
                                     "o caminho lógico solicitado é inválido"));
    }
    const auto canonical = requested == "/" ? std::string_view{} : requested;
    const auto* row = observed.history_present
                          ? find_row(observed.effective_tree, canonical)
                          : nullptr;
    if (row == nullptr) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::RemotePathNotFound,
                                     "o caminho não existe na árvore lógica "
                                     "remota"));
    }
    return RemoteStatReport{
        .observed_height = observed.observed_height,
        .has_conflicts = observed.has_conflicts,
        .path = row->path.empty() ? "/" : row->path,
        .type = row->is_directory ? RemoteTreeEntryType::Directory
                                  : RemoteTreeEntryType::File,
        .logical_hash = hash_hex(row->hash),
        .size = row->size,
        .modified_at_unix_nanoseconds = unix_nanoseconds(*row),
    };
}

std::expected<std::filesystem::path, InspectionError>
resolve_destination(const InspectionRequest& request,
                    InspectionOperation operation) {
    const auto requested = request.destination_path.value_or("");
    if (requested.empty()) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::InvalidRequest,
                                     "o destino solicitado é inválido"));
    }
    std::error_code filesystem_error;
    auto destination = std::filesystem::absolute(requested, filesystem_error)
                           .lexically_normal();
    if (filesystem_error || destination.filename().empty()) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::DestinationFailure,
                                     "não foi possível resolver o destino"));
    }
    const auto parent_status = std::filesystem::symlink_status(
        destination.parent_path(), filesystem_error);
    if (filesystem_error || std::filesystem::is_symlink(parent_status) ||
        !std::filesystem::is_directory(parent_status)) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::DestinationFailure,
                  "o diretório pai do destino não existe ou não é seguro"));
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
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::DestinationFailure,
                  "o destino não é um arquivo regular seguro"));
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
                                     "não foi possível preparar o destino"));
    }
    const auto temporary =
        destination.parent_path() / (".kasumi-download-" + *token + ".tmp");
    const auto cleanup = [&] {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
    };
    std::error_code filesystem_error;
    if (!std::filesystem::copy_file(plaintext,
                                    temporary,
                                    std::filesystem::copy_options::none,
                                    filesystem_error)) {
        cleanup();
        return std::unexpected(error(operation,
                                     InspectionErrorCode::DestinationFailure,
                                     "não foi possível preparar o arquivo de "
                                     "destino"));
    }
    if (auto synced = platform::durability::sync_file(temporary); !synced) {
        cleanup();
        return std::unexpected(error(operation,
                                     InspectionErrorCode::DestinationFailure,
                                     "não foi possível persistir o download"));
    }
    if (auto replaced =
            platform::durability::replace_atomically(temporary, destination);
        !replaced) {
        cleanup();
        return std::unexpected(error(operation,
                                     InspectionErrorCode::DestinationFailure,
                                     "não foi possível instalar o download"));
    }
    if (auto synced = platform::durability::sync_parent_directory(destination);
        !synced) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::DestinationFailure,
                                     "não foi possível persistir o destino"));
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
                                     "o caminho não existe na árvore lógica "
                                     "remota"));
    }
    if (row->is_directory) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::RemotePathIsDirectory,
                                     "o caminho remoto é um diretório"));
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
                      ? "o conteúdo remoto do arquivo não foi encontrado"
                      : "não foi possível baixar o conteúdo remoto"));
    }
    if (!crypto::decrypt_file(encrypted, plaintext, context.key) ||
        !crypto::content::verify_file(plaintext, logical_hash, row->size)) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteContentInvalid,
                  "o conteúdo remoto falhou na autenticação criptográfica"));
    }
    if (auto installed =
            install_remote_file(plaintext, *destination, operation);
        !installed) {
        return std::unexpected(installed.error());
    }
    return RemoteFileReport{.path = row->path,
                            .destination_path = destination->string(),
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
                  "não foi possível autenticar a cadeia remota de Epochs"));
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
                                     "o Epoch remoto solicitado não existe"));
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
                  "o inventário lógico de conteúdo é inconsistente"));
    }
    for (const auto& commit : observed.reachable_commits) {
        if (!add_rows(commit.commit.tree, false)) {
            return std::unexpected(error(
                operation,
                InspectionErrorCode::RemoteObservationFailure,
                "o histórico possui metadados de conteúdo inconsistentes"));
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

        const auto encrypted =
            context.workspace->root /
            ("content-audit-" + std::to_string(audit_index) + ".enc");
        const auto plaintext =
            context.workspace->root /
            ("content-audit-" + std::to_string(audit_index++) + ".plain");
        auto downloaded =
            transport::get(context.storage, content.content_id, encrypted);
        if (!downloaded) {
            if (downloaded.error().code ==
                transport::ErrorCode::ObjectNotFound) {
                content.physically_present = false;
                content.state = RemoteContentState::Missing;
                continue;
            }
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::RemoteObservationFailure,
                      "não foi possível baixar um objeto durante a auditoria"));
        }
        if (!crypto::decrypt_file(encrypted, plaintext, context.key)) {
            content.state = RemoteContentState::Invalid;
            continue;
        }
        const auto hash = crypto::content::hash_file(plaintext);
        std::error_code filesystem_error;
        const auto size =
            std::filesystem::file_size(plaintext, filesystem_error);
        if (!hash || filesystem_error ||
            crypto::content_identifier(context.key, *hash) !=
                content.content_id ||
            (content.referenced && (hash_hex(*hash) != content.logical_hash ||
                                    size != content.size))) {
            content.state = RemoteContentState::Invalid;
            continue;
        }
        if (!content.referenced) {
            content.logical_hash = hash_hex(*hash);
            content.size = size;
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
constexpr std::string_view gc_prefix = "history/gc/v1/";
constexpr std::string_view writer_prefix = "history/gc/v1/writers/";
constexpr std::string_view probe_prefix = "history/gc/v1/probes/";
constexpr std::string_view quarantine_prefix = "history/gc/v1/quarantine/";
constexpr std::string_view barrier_identifier = "history/gc/v1/barrier";

std::expected<std::vector<std::string>, InspectionError>
physical_objects(InspectionContext& context, InspectionOperation operation) {
    auto listed = transport::list(context.storage);
    if (!listed) {
        if (listed.error().code == transport::ErrorCode::StorageNotFound) {
            return std::vector<std::string>{};
        }
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "não foi possível listar os objetos remotos"));
    }
    if (listed->size() > maximum_physical_object_count) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "o namespace remoto excede o limite defensivo"));
    }
    std::ranges::sort(*listed);
    listed->erase(std::ranges::unique(*listed).begin(), listed->end());
    return std::move(*listed);
}

bool valid_writer(std::string_view identifier) {
    if (!identifier.starts_with(writer_prefix)) {
        return false;
    }
    const auto name = identifier.substr(writer_prefix.size());
    return name.size() == 39 && name.ends_with(".writer") &&
           std::ranges::all_of(name.substr(0, 32), [](char value) {
               return (value >= '0' && value <= '9') ||
                      (value >= 'a' && value <= 'f');
           });
}

RemoteObjectInfo classify_object(std::string identifier) {
    RemoteObjectInfo result{.identifier = std::move(identifier),
                            .relation = "não auditado"};
    const auto& id = result.identifier;
    if (history::valid_commit_id(id)) {
        result.category = RemoteObjectCategory::Content;
        result.structurally_valid = true;
    } else if (history_storage::detail::parse_commit_object(id)) {
        result.category = RemoteObjectCategory::CommitVariant;
        result.structurally_valid = true;
    } else if (id.starts_with(history_storage::detail::heads_prefix)) {
        result.category = RemoteObjectCategory::HeadMarker;
        result.structurally_valid =
            history_storage::parse_marker_object(id).has_value();
    } else if (id.starts_with(history_storage::maintenance_protocol::
                                  epoch_namespace_prefix)) {
        result.category = RemoteObjectCategory::Epoch;
        result.structurally_valid =
            history_storage::epoch::parse_object_identifier(id).has_value();
    } else if (id == barrier_identifier) {
        result.category = RemoteObjectCategory::Barrier;
        result.structurally_valid = true;
        result.relation = "barreira de manutenção";
    } else if (id.starts_with(writer_prefix)) {
        result.category = RemoteObjectCategory::Writer;
        result.structurally_valid = valid_writer(id);
        result.relation = "bloqueia manutenção enquanto presente";
    } else if (id.starts_with(quarantine_prefix) && id.ends_with(".meta")) {
        result.category = RemoteObjectCategory::RetentionMetadata;
        result.structurally_valid = true;
    } else if (id.starts_with(quarantine_prefix)) {
        result.category = RemoteObjectCategory::Quarantine;
        result.structurally_valid = true;
    } else if (id.starts_with(probe_prefix)) {
        result.category = RemoteObjectCategory::Protocol;
        result.structurally_valid = true;
    } else if (id.starts_with(gc_prefix)) {
        result.category = RemoteObjectCategory::Protocol;
    }
    return result;
}

RemoteObjectsReport make_objects_report(std::vector<std::string> identifiers) {
    RemoteObjectsReport report;
    report.objects.reserve(identifiers.size());
    for (auto& identifier : identifiers) {
        auto object = classify_object(std::move(identifier));
        if (object.category == RemoteObjectCategory::Unknown ||
            !object.structurally_valid) {
            ++report.unknown_count;
        }
        report.objects.push_back(std::move(object));
    }
    return report;
}

std::expected<history_storage::ReachabilityInventory, InspectionError>
reachability(
    InspectionContext& context,
    InspectionOperation operation,
    std::optional<std::span<const std::string>> identifiers = std::nullopt,
    std::optional<std::span<const history_storage::epoch::VerifiedEpoch>>
        verified_epochs = std::nullopt) {
    auto inventory =
        identifiers && verified_epochs
            ? history_storage::inventory_reachability(context.storage,
                                                      context.key,
                                                      *identifiers,
                                                      *verified_epochs,
                                                      context.workspace->root)
        : identifiers
            ? history_storage::inventory_reachability(context.storage,
                                                      context.key,
                                                      *identifiers,
                                                      context.workspace->root)
            : history_storage::inventory_reachability(
                  context.storage, context.key, context.workspace->root);
    if (!inventory) {
        return std::unexpected(error(
            operation,
            InspectionErrorCode::RemoteObservationFailure,
            "não foi possível autenticar o inventário físico do histórico"));
    }
    return std::move(*inventory);
}

std::set<std::string>
ancestral_markers(const history_storage::ReachabilityInventory& inventory) {
    std::map<std::string, const history_storage::ReachabilityCommit*> commits;
    for (const auto& commit : inventory.commits) {
        commits.emplace(commit.commit_id, &commit);
    }
    std::set<std::string> marked;
    for (const auto& marker : inventory.markers) {
        if (marker.state == history_storage::ReachabilityMarkerState::Valid &&
            marker.reference) {
            marked.insert(marker.reference->commit_id);
        }
    }
    std::set<std::string> ancestral;
    for (const auto& root : marked) {
        const auto found = commits.find(root);
        if (found == commits.end()) {
            continue;
        }
        std::vector<std::string> pending = found->second->parents;
        std::set<std::string> visited;
        while (!pending.empty()) {
            auto current = std::move(pending.back());
            pending.pop_back();
            if (!visited.insert(current).second) {
                continue;
            }
            if (marked.contains(current)) {
                ancestral.insert(current);
            }
            const auto parent = commits.find(current);
            if (parent != commits.end()) {
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

std::expected<history_storage::ContentReachabilityInventory, InspectionError>
content_reachability(
    InspectionContext& context,
    InspectionOperation operation,
    const history_storage::ReachabilityInventory& history_inventory,
    std::optional<std::span<const std::string>> identifiers = std::nullopt) {
    auto inventory = identifiers
                         ? history_storage::inventory_content_reachability(
                               context.storage,
                               context.key,
                               *identifiers,
                               history_inventory,
                               context.workspace->root)
                         : history_storage::inventory_content_reachability(
                               context.storage,
                               context.key,
                               history_inventory,
                               context.workspace->root);
    if (!inventory) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "não foi possível auditar o alcance dos conteúdos remotos"));
    }
    return std::move(*inventory);
}

RemoteOrphansReport make_orphans_report(
    const history_storage::ReachabilityInventory& history_inventory,
    const history_storage::ContentReachabilityInventory& content_inventory) {
    RemoteOrphansReport report;
    std::set<std::string> marked_variants;
    for (const auto& marker : history_inventory.markers) {
        if (marker.state == history_storage::ReachabilityMarkerState::Valid &&
            marker.reference) {
            marked_variants.insert(
                history_storage::detail::commit_object(*marker.reference));
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
make_writers_report(const std::vector<std::string>& identifiers) {
    RemoteWritersReport report;
    report.barrier_present =
        std::ranges::find(identifiers, barrier_identifier) != identifiers.end();
    for (const auto& identifier : identifiers) {
        if (!identifier.starts_with(writer_prefix)) {
            continue;
        }
        const auto state = valid_writer(identifier)
                               ? RemoteWriterState::Indeterminate
                               : RemoteWriterState::Invalid;
        report.protocol_consistent &= state != RemoteWriterState::Invalid;
        report.writers.push_back(
            RemoteWriterInfo{.identifier = identifier, .state = state});
    }
    for (const auto& identifier : identifiers) {
        if (identifier.starts_with(gc_prefix) &&
            identifier != barrier_identifier &&
            !identifier.starts_with(writer_prefix) &&
            !identifier.starts_with(probe_prefix) &&
            !identifier.starts_with(quarantine_prefix)) {
            report.protocol_consistent = false;
        }
    }
    report.maintenance_blocked =
        report.barrier_present || !report.writers.empty();
    return report;
}

std::expected<RemoteQuarantineReport, InspectionError> make_quarantine_report(
    InspectionContext& context,
    InspectionOperation operation,
    std::optional<std::span<const std::string>> identifiers = std::nullopt) {
    auto inventory =
        identifiers
            ? history_storage::maintenance_protocol::inventory_quarantine(
                  context.storage,
                  context.key,
                  *identifiers,
                  context.workspace->root)
            : history_storage::maintenance_protocol::inventory_quarantine(
                  context.storage, context.key, context.workspace->root);
    if (!inventory) {
        return std::unexpected(error(
            operation,
            InspectionErrorCode::RemoteObservationFailure,
            "a quarentena remota possui metadata inválida ou inacessível"));
    }
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    RemoteQuarantineReport report;
    report.entries.reserve(inventory->size());
    for (const auto& entry : *inventory) {
        const bool authenticated =
            entry.quarantined_at.has_value() && !entry.physical_sha256.empty();
        report.entries.push_back(RemoteQuarantineInfo{
            .original_identifier = entry.original_identifier,
            .quarantine_identifier = entry.quarantine_identifier,
            .metadata_identifier = entry.metadata_identifier,
            .category = entry.original_identifier.starts_with(
                            history_storage::detail::commit_prefix)
                            ? "commit"
                            : "conteúdo",
            .metadata_authenticated = authenticated,
            .quarantined_at = entry.quarantined_at.value_or(0),
            .retention_elapsed =
                authenticated && *entry.quarantined_at <=
                                     now -
                                         history_storage::maintenance_protocol::
                                             quarantine_retention_seconds});
    }
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
                  "não foi possível autenticar a continuidade dos Epochs"));
    }
    auto history_inventory =
        reachability(context, operation, identifiers, *epochs);
    if (!history_inventory) {
        return std::unexpected(history_inventory.error());
    }
    auto content_inventory = content_reachability(
        context, operation, *history_inventory, identifiers);
    if (!content_inventory) {
        return std::unexpected(content_inventory.error());
    }
    auto quarantine = make_quarantine_report(context, operation, identifiers);
    if (!quarantine) {
        return std::unexpected(quarantine.error());
    }
    const auto markers = make_markers_report(*history_inventory);
    const auto objects = make_objects_report(identifiers);
    const auto writers = make_writers_report(identifiers);
    const auto orphans =
        make_orphans_report(*history_inventory, *content_inventory);

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
        .quarantine_count = quarantine->entries.size(),
        .unknown_object_count = objects.unknown_count,
    };
    report.invalid_content_count =
        static_cast<std::size_t>(std::ranges::count_if(
            content_inventory->contents, [](const auto& content) {
                return content.reachable &&
                       content.state ==
                           history_storage::ContentObjectState::Corrupt;
            }));

    const auto add_reason = [&](bool condition, std::string reason) {
        if (condition) {
            report.reasons.push_back(std::move(reason));
        }
    };
    add_reason(markers.invalid_count != 0,
               "markers físicos inválidos: " +
                   std::to_string(markers.invalid_count));
    add_reason(
        !history_inventory->missing_parent_ids.empty(),
        "pais de commit ausentes: " +
            std::to_string(history_inventory->missing_parent_ids.size()));
    add_reason(
        !history_inventory->invalid_parent_ids.empty(),
        "pais de commit inválidos: " +
            std::to_string(history_inventory->invalid_parent_ids.size()));
    add_reason(report.missing_content_count != 0,
               "conteúdos necessários ausentes: " +
                   std::to_string(report.missing_content_count));
    add_reason(report.invalid_content_count != 0,
               "conteúdos necessários inválidos: " +
                   std::to_string(report.invalid_content_count));
    add_reason(!writers.protocol_consistent,
               "protocolo de manutenção inconsistente");
    const auto critical_reason_count = report.reasons.size();
    add_reason(report.orphan_count != 0,
               "objetos sem alcance: " + std::to_string(report.orphan_count));
    add_reason(report.unknown_object_count != 0,
               "objetos desconhecidos: " +
                   std::to_string(report.unknown_object_count));
    add_reason(writers.maintenance_blocked, "manutenção atualmente bloqueada");
    report.state = critical_reason_count != 0 ? RemoteHealthState::Critical
                   : report.reasons.empty()   ? RemoteHealthState::Healthy
                                              : RemoteHealthState::Degraded;
    return report;
}

std::expected<InspectionResponse, InspectionError>
inspect_physical(InspectionContext& context, InspectionOperation operation) {
    if (operation == InspectionOperation::RemoteMarkers) {
        auto inventory = reachability(context, operation);
        if (!inventory) {
            return std::unexpected(inventory.error());
        }
        return InspectionResponse{.operation = operation,
                                  .payload = make_markers_report(*inventory)};
    }
    if (operation == InspectionOperation::RemoteOrphans) {
        auto identifiers = physical_objects(context, operation);
        if (!identifiers) {
            return std::unexpected(identifiers.error());
        }
        auto history_inventory = reachability(context, operation, *identifiers);
        if (!history_inventory) {
            return std::unexpected(history_inventory.error());
        }
        auto contents = content_reachability(
            context, operation, *history_inventory, *identifiers);
        if (!contents) {
            return std::unexpected(contents.error());
        }
        return InspectionResponse{
            .operation = operation,
            .payload = make_orphans_report(*history_inventory, *contents)};
    }
    if (operation == InspectionOperation::RemoteQuarantine) {
        auto report = make_quarantine_report(context, operation);
        if (!report) {
            return std::unexpected(report.error());
        }
        return InspectionResponse{.operation = operation,
                                  .payload = std::move(*report)};
    }

    auto identifiers = physical_objects(context, operation);
    if (!identifiers) {
        return std::unexpected(identifiers.error());
    }
    if (operation == InspectionOperation::RemoteObjects) {
        return InspectionResponse{
            .operation = operation,
            .payload = make_objects_report(std::move(*identifiers))};
    }
    if (operation == InspectionOperation::RemoteWriters) {
        return InspectionResponse{.operation = operation,
                                  .payload = make_writers_report(*identifiers)};
    }
    auto health = make_health_report(context, operation, *identifiers);
    if (!health) {
        return std::unexpected(health.error());
    }
    return InspectionResponse{.operation = operation,
                              .payload = std::move(*health)};
}

RemoteCommitInfo
commit_info(const kasumi::history::LoadedCommit& loaded,
            const observation::history::StorageView& observed) {
    const auto& rows = loaded.commit.tree.rows;
    return RemoteCommitInfo{
        .commit_id = loaded.id,
        .height = loaded.commit.height,
        .created_at = loaded.commit.created_at,
        .parent_ids = loaded.commit.parents,
        .logical_head = std::ranges::find(observed.logical_heads, loaded.id) !=
                        observed.logical_heads.end(),
        .physically_marked =
            std::ranges::find(observed.marked_heads, loaded.id) !=
            observed.marked_heads.end(),
        .ancestral_marked =
            std::ranges::find(observed.ancestral_marked_heads, loaded.id) !=
            observed.ancestral_marked_heads.end(),
        .root_hash = hash_hex(rows.front().hash),
        .total_bytes = rows.front().size,
        .entry_count = static_cast<std::uint64_t>(rows.size() - 1),
    };
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
                                     "o commit não é alcançável no histórico "
                                     "remoto atual"));
    }
    if (selected->commit.tree.rows.empty() ||
        !valid_snapshot(selected->commit.tree, false)) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "o commit remoto não possui uma árvore válida"));
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
        return std::unexpected(error(
            operation,
            InspectionErrorCode::RemoteObservationFailure,
            "não foi possível autenticar as variantes físicas do commit"));
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
    if ((input.request.head_commit_id &&
         operation != InspectionOperation::RemoteTree) ||
        (input.request.logical_path &&
         operation != InspectionOperation::RemoteStat &&
         operation != InspectionOperation::RemoteGet) ||
        (input.request.commit_id &&
         operation != InspectionOperation::RemoteCommit) ||
        (input.request.destination_path &&
         operation != InspectionOperation::RemoteGet) ||
        (input.request.epoch_selector &&
         operation != InspectionOperation::RemoteEpoch) ||
        (input.request.content_id &&
         operation != InspectionOperation::RemoteContent)) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::InvalidRequest,
                  "o seletor não pertence à operação de inspeção solicitada"));
    }
    if (operation == InspectionOperation::RemoteStat &&
        (!input.request.logical_path ||
         !valid_logical_path(*input.request.logical_path))) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::InvalidRequest,
                                     "o caminho lógico solicitado é inválido"));
    }
    if (operation == InspectionOperation::RemoteGet &&
        (!input.request.logical_path ||
         !valid_logical_path(*input.request.logical_path) ||
         *input.request.logical_path == "/" ||
         !input.request.destination_path ||
         input.request.destination_path->empty())) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::InvalidRequest,
                                     "o caminho remoto ou destino é inválido"));
    }
    if (operation == InspectionOperation::RemoteCommit &&
        (!input.request.commit_id ||
         !history::valid_commit_id(*input.request.commit_id))) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::InvalidRequest,
                                     "o ID de commit solicitado é inválido"));
    }
    if (operation == InspectionOperation::RemoteEpoch &&
        (!input.request.epoch_selector ||
         (!history::valid_commit_id(*input.request.epoch_selector) &&
          !epoch_sequence(*input.request.epoch_selector)))) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::InvalidRequest,
                                     "o ID ou sequência de Epoch é inválido"));
    }
    if (operation == InspectionOperation::RemoteContent &&
        (!input.request.content_id ||
         !history::valid_commit_id(*input.request.content_id))) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::InvalidRequest,
                                     "o content ID solicitado é inválido"));
    }
    if (operation != InspectionOperation::RemoteHeads &&
        operation != InspectionOperation::RemoteTree &&
        operation != InspectionOperation::RemoteCommits &&
        operation != InspectionOperation::RemoteSummary &&
        operation != InspectionOperation::RemoteStat &&
        operation != InspectionOperation::RemoteCommit &&
        operation != InspectionOperation::RemoteGet &&
        operation != InspectionOperation::RemoteEpochs &&
        operation != InspectionOperation::RemoteEpoch &&
        operation != InspectionOperation::RemoteContents &&
        operation != InspectionOperation::RemoteContentsAudit &&
        operation != InspectionOperation::RemoteContent &&
        operation != InspectionOperation::RemoteMarkers &&
        operation != InspectionOperation::RemoteObjects &&
        operation != InspectionOperation::RemoteOrphans &&
        operation != InspectionOperation::RemoteQuarantine &&
        operation != InspectionOperation::RemoteWriters &&
        operation != InspectionOperation::RemoteHealth) {
        return std::unexpected(error(operation,
                                     InspectionErrorCode::RuntimeFailure,
                                     "operação de inspeção desconhecida"));
    }

    const auto runtime_trace = platform::perf_trace::begin();
    auto runtime_data = runtime::resolve(input.environment.app_data_dir,
                                         input.request.profile_name,
                                         runtime::AccessMode::ReadOnly,
                                         false);
    platform::perf_trace::finish("inspection runtime resolve", runtime_trace);
    if (!runtime_data) {
        return std::unexpected(
            map_runtime_error(operation, runtime_data.error()));
    }
    context.runtime = *runtime_data;

    const auto credential_trace = platform::perf_trace::begin();
    auto key =
        resolve_key(input.credentials, context.runtime, context.key, operation);
    platform::perf_trace::finish("inspection credential resolve",
                                 credential_trace);
    if (!key) {
        return std::unexpected(key.error());
    }

    context.hints =
        make_observation_hints(context.runtime, operation, context.key);
    if (!context.hints.frontier) {
        platform::perf_trace::count("inspection cold observation");
    }
    if (requires_complete_history(operation) && !context.hints.history_cache) {
        platform::perf_trace::count("inspection full history observation");
    }

    const auto transport_trace = platform::perf_trace::begin();
    auto opened = transport::open_transport(context.runtime.storage_location,
                                            context.runtime.local_dir);
    platform::perf_trace::finish("inspection transport open", transport_trace);
    if (!opened) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RuntimeFailure,
                  "não foi possível abrir o armazenamento remoto"));
    }
    context.storage = std::move(*opened);

    const auto workspace_trace = platform::perf_trace::begin();
    auto workspace = platform::create_workspace("remote-inspection");
    platform::perf_trace::finish("inspection workspace", workspace_trace);
    if (!workspace) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "não foi possível preparar a observação remota"));
    }
    context.workspace = std::move(*workspace);

    if (operation == InspectionOperation::RemoteEpochs ||
        operation == InspectionOperation::RemoteEpoch) {
        return inspect_epochs(input.request, context, operation);
    }
    if (operation == InspectionOperation::RemoteMarkers ||
        operation == InspectionOperation::RemoteObjects ||
        operation == InspectionOperation::RemoteOrphans ||
        operation == InspectionOperation::RemoteQuarantine ||
        operation == InspectionOperation::RemoteWriters ||
        operation == InspectionOperation::RemoteHealth) {
        return inspect_physical(context, operation);
    }

    const bool audit_content_objects =
        operation == InspectionOperation::RemoteSummary ||
        operation == InspectionOperation::RemoteContents ||
        operation == InspectionOperation::RemoteContentsAudit ||
        operation == InspectionOperation::RemoteContent;
    const auto observe_remote = [&](const auto* frontier) {
        return observation::history::observe(
            context.storage,
            context.key,
            context.workspace->root,
            audit_content_objects,
            frontier,
            context.hints.trusted_marker_identifiers,
            requires_complete_history(operation));
    };
    const auto remote_trace = platform::perf_trace::begin();
    auto observed = observe_remote(
        context.hints.frontier ? &*context.hints.frontier : nullptr);
    if (context.hints.history_cache &&
        (!observed ||
         !merge_history_cache(*observed, *context.hints.history_cache))) {
        platform::perf_trace::count("inspection history cache fallback");
        observed = observe_remote(
            static_cast<const history_storage::KnownHistoryFrontier*>(nullptr));
        context.hints.history_cache.reset();
    }
    platform::perf_trace::finish("inspection remote observation", remote_trace);
    if (!observed) {
        return std::unexpected(
            error(operation,
                  InspectionErrorCode::RemoteObservationFailure,
                  "não foi possível observar o histórico remoto"));
    }
    if (requires_complete_history(operation)) {
        if (context.hints.history_cache &&
            observed->authenticated_commit_variants.empty()) {
            platform::perf_trace::count("inspection history cache unchanged");
        } else if (save_history_cache(
                       context.runtime, context.key, *observed)) {
            platform::perf_trace::count("inspection history cache saved");
        } else {
            platform::perf_trace::count("inspection history cache not saved");
        }
    }

    if (operation == InspectionOperation::RemoteContents ||
        operation == InspectionOperation::RemoteContentsAudit ||
        operation == InspectionOperation::RemoteContent) {
        auto contents = inspect_contents(
            *observed,
            context,
            operation,
            operation == InspectionOperation::RemoteContentsAudit);
        if (!contents) {
            return std::unexpected(contents.error());
        }
        if (operation != InspectionOperation::RemoteContent) {
            return InspectionResponse{.operation = operation,
                                      .payload = std::move(*contents)};
        }
        const auto selected = std::ranges::find(contents->contents,
                                                *input.request.content_id,
                                                &RemoteContentInfo::content_id);
        if (selected == contents->contents.end()) {
            return std::unexpected(error(
                operation,
                InspectionErrorCode::RemoteContentNotFound,
                "o content ID solicitado não existe no inventário remoto"));
        }
        return InspectionResponse{
            .operation = operation,
            .payload = RemoteContentReport{.content = std::move(*selected)}};
    }

    if (operation == InspectionOperation::RemoteHeads) {
        const auto report_trace = platform::perf_trace::begin();
        auto heads = make_head_infos(*observed, operation);
        if (!heads) {
            platform::perf_trace::finish("inspection report build",
                                         report_trace);
            return std::unexpected(heads.error());
        }
        RemoteHeadsReport report{
            .history_present = observed->history_present,
            .observed_height = observed->observed_height,
            .physical_marker_count = observed->marked_head_identifiers.size(),
            .ancestral_marker_count = observed->ancestral_marked_heads.size(),
            .heads = std::move(*heads),
        };
        platform::perf_trace::finish("inspection report build", report_trace);
        return InspectionResponse{.operation = operation,
                                  .payload = std::move(report)};
    }

    if (operation == InspectionOperation::RemoteTree) {
        const auto report_trace = platform::perf_trace::begin();
        auto heads = make_head_infos(*observed, operation);
        if (!heads) {
            platform::perf_trace::finish("inspection report build",
                                         report_trace);
            return std::unexpected(heads.error());
        }
        auto tree =
            make_tree_report(input.request, *observed, *heads, operation);
        if (!tree) {
            platform::perf_trace::finish("inspection report build",
                                         report_trace);
            return std::unexpected(tree.error());
        }
        platform::perf_trace::finish("inspection report build", report_trace);
        return InspectionResponse{.operation = operation,
                                  .payload = std::move(*tree)};
    }

    if (operation == InspectionOperation::RemoteSummary) {
        const auto report_trace = platform::perf_trace::begin();
        auto writers = history_storage::maintenance_protocol::active_writers(
            context.storage);
        if (!writers) {
            platform::perf_trace::finish("inspection report build",
                                         report_trace);
            return std::unexpected(
                error(operation,
                      InspectionErrorCode::RemoteObservationFailure,
                      "não foi possível observar os writers remotos"));
        }
        RemoteSummaryReport report{
            .history_present = observed->history_present,
            .observed_height = observed->observed_height,
            .reachable_commit_count = observed->reachable_commit_ids.size(),
            .logical_head_count = observed->logical_heads.size(),
            .has_conflicts = observed->has_conflicts,
            .missing_content_count = observed->missing_content_count,
            .orphan_content_count = observed->orphan_content_count,
            .active_writer_count = writers->size(),
        };
        platform::perf_trace::finish("inspection report build", report_trace);
        return InspectionResponse{.operation = operation,
                                  .payload = std::move(report)};
    }

    if (operation == InspectionOperation::RemoteStat) {
        const auto report_trace = platform::perf_trace::begin();
        auto stat = make_stat_report(input.request, *observed, operation);
        platform::perf_trace::finish("inspection report build", report_trace);
        if (!stat) {
            return std::unexpected(stat.error());
        }
        return InspectionResponse{.operation = operation,
                                  .payload = std::move(*stat)};
    }

    if (operation == InspectionOperation::RemoteCommit) {
        const auto report_trace = platform::perf_trace::begin();
        auto commit =
            make_commit_report(input.request, *observed, context, operation);
        platform::perf_trace::finish("inspection report build", report_trace);
        if (!commit) {
            return std::unexpected(commit.error());
        }
        return InspectionResponse{.operation = operation,
                                  .payload = std::move(*commit)};
    }

    if (operation == InspectionOperation::RemoteGet) {
        const auto report_trace = platform::perf_trace::begin();
        auto file =
            download_remote_file(input.request, *observed, context, operation);
        platform::perf_trace::finish("inspection remote file", report_trace);
        if (!file) {
            return std::unexpected(file.error());
        }
        return InspectionResponse{.operation = operation,
                                  .payload = std::move(*file)};
    }

    const auto report_trace = platform::perf_trace::begin();
    auto commits = make_commits_report(*observed, operation);
    if (!commits) {
        platform::perf_trace::finish("inspection report build", report_trace);
        return std::unexpected(commits.error());
    }
    platform::perf_trace::finish("inspection report build", report_trace);
    return InspectionResponse{.operation = operation,
                              .payload = std::move(*commits)};
}

void finish_inspection(InspectionInput& input, InspectionContext& context) {
    if (context.workspace) {
        platform::cleanup_workspace(*context.workspace);
        context.workspace.reset();
    }
    const auto shutdown_trace = platform::perf_trace::begin();
    context.storage = {};
    platform::perf_trace::finish("inspection transport shutdown",
                                 shutdown_trace);
    crypto::secure_memory::wipe(context.key.data(), context.key.size());
    wipe_credentials(input.credentials);
}

} // namespace

std::expected<InspectionResponse, InspectionError>
inspect(InspectionInput input) {
    platform::perf_trace::reset();
    const auto total_trace = platform::perf_trace::begin();
    InspectionContext context;
    std::expected<InspectionResponse, InspectionError> result =
        std::unexpected(error(input.request.operation,
                              InspectionErrorCode::RuntimeFailure,
                              "falha na inspeção remota"));
    try {
        result = run_inspection(input, context);
    } catch (const std::exception&) {
        result = std::unexpected(error(input.request.operation,
                                       InspectionErrorCode::RuntimeFailure,
                                       "exceção durante a inspeção remota"));
    } catch (...) {
        result = std::unexpected(error(input.request.operation,
                                       InspectionErrorCode::RuntimeFailure,
                                       "exceção durante a inspeção remota"));
    }
    finish_inspection(input, context);
    platform::perf_trace::finish("total inspection", total_trace);
    platform::perf_trace::report(result ? "inspection-success"
                                        : "inspection-error");
    return result;
}

std::expected<InspectionResponse, InspectionError>
read_remote_file(InspectionInput input) {
    if (input.request.operation != InspectionOperation::RemoteGet) {
        const auto result = std::unexpected(
            error(input.request.operation,
                  InspectionErrorCode::InvalidRequest,
                  "read_remote_file exige a operação RemoteGet"));
        wipe_credentials(input.credentials);
        return result;
    }
    return inspect(std::move(input));
}

} // namespace kasumi::application
