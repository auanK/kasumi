#include "application/sync/coordinator.hpp"

#include "application/history_storage/epoch.hpp"
#include "application/observation/scanner.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/metadata.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_batch.hpp"
#include "application/sync/publication.hpp"
#include "coordinator_detail.hpp"
#include "core/history.hpp"
#include "core/reconciliation/plan.hpp"
#include "core/transaction/types.hpp"
#include "platform/clock.hpp"
#include "platform/durability.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <future>
#include <limits>
#include <mutex>
#include <optional>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace kasumi::application::sync::coordinator {
namespace detail {

inline constexpr std::array<std::string_view, ActionCount> action_metrics{
    "action/RenameLocal",
    "action/Upload",
    "action/CreateLocalDirectory",
    "action/CreateRemoteDirectory",
    "action/Download",
    "action/DeleteLocal",
    "action/DeleteLocalDirectory",
    "action/DeleteRemote",
    "action/DeleteRemoteDirectory",
};

Error make_error(ErrorCode code,
                 std::string detail,
                 std::optional<std::size_t> operation_index) {
    return Error{.code = code,
                 .detail = std::move(detail),
                 .operation_index = operation_index};
}

Error journal_error(std::string detail) {
    return make_error(ErrorCode::JournalFailure, std::move(detail));
}

Error indeterminate_publication(const publication::Error& error,
                                std::string_view operation) {
    return make_error(ErrorCode::RecoveryIndeterminate,
                      "não foi possível determinar " + std::string{operation} + ": " +
                          error.detail);
}

bool missing(std::filesystem::file_status status) noexcept {
    return status.type() == std::filesystem::file_type::not_found;
}

Error workspace_error(std::string_view operation,
                      const std::filesystem::path& path,
                      std::string detail) {
    return make_error(ErrorCode::WorkspaceFailure,
                      std::string{operation} + " '" + platform::path::to_utf8(path) +
                          "': " + std::move(detail));
}

std::expected<std::filesystem::file_status, Error>
read_status(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory) {
        return std::filesystem::file_status{
            std::filesystem::file_type::not_found};
    }
    if (error) {
        return std::unexpected(workspace_error(
            "não foi possível inspecionar o caminho no sistema de arquivos", path, error.message()));
    }
    return status;
}

std::expected<std::filesystem::path, Error>
profile_directory(const runtime::RuntimeData& runtime_data) {
    const auto profile = runtime_data.database_path.parent_path();
    if (profile.empty() || profile == "." || profile == "..") {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput, "invalid profile directory"));
    }
    return profile.lexically_normal();
}

std::expected<std::filesystem::path, Error>
transactions_directory(const std::filesystem::path& profile, bool create) {
    auto status = read_status(profile);
    if (!status || missing(*status) || std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_directory(*status)) {
        if (!status) {
            return std::unexpected(status.error());
        }
        return std::unexpected(
            workspace_error("invalid profile directory",
                            profile,
                            "expected a physical directory"));
    }
    const auto directory = profile / ".transactions";
    status = read_status(directory);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (missing(*status)) {
        if (!create) {
            return directory;
        }
        auto created = platform::private_storage::create_directory(directory);
        if (!created) {
            return std::unexpected(
                workspace_error("não foi possível criar o diretório de transações",
                                directory,
                                created.error()));
        }
        return directory;
    }
    if (std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_directory(*status)) {
        return std::unexpected(
            workspace_error("diretório de transações inválido",
                            directory,
                            "esperava-se um diretório físico"));
    }
    auto secured = platform::private_storage::protect_directory(directory);
    if (!secured) {
        return std::unexpected(workspace_error(
            "diretório de transações inválido", directory, secured.error()));
    }
    return directory;
}

std::expected<platform::Workspace, Error>
create_transaction_workspace(const std::filesystem::path& profile,
                             std::string_view id) {
    if (!transaction::valid_transaction_id(id)) {
        return std::unexpected(
            make_error(ErrorCode::WorkspaceFailure, "identificador de transação inválido"));
    }
    auto directory = transactions_directory(profile, true);
    if (!directory) {
        return std::unexpected(directory.error());
    }
    const auto root = *directory / platform::path::from_utf8(id);
    auto status = read_status(root);
    if (status && !missing(*status)) {
        if (std::filesystem::is_symlink(*status) ||
            !std::filesystem::is_directory(*status)) {
            return std::unexpected(workspace_error(
                "espaço de trabalho da transação inválido",
                root,
                "esperava-se um diretório físico"));
        }
        return platform::Workspace{.root = root};
    }
    auto created = platform::private_storage::create_directory(root);
    if (!created) {
        return std::unexpected(workspace_error(
            "não foi possível criar o espaço de trabalho da transação", root, created.error()));
    }
    return platform::Workspace{.root = root};
}

std::expected<void, Error> remove_transaction_workspace(
    const std::optional<platform::Workspace>& workspace) {
    if (!workspace || workspace->root.empty()) {
        return {};
    }
    auto status = read_status(workspace->root);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (missing(*status)) {
        return {};
    }
    if (std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_directory(*status)) {
        return std::unexpected(
            workspace_error("espaço de trabalho da transação inválido",
                            workspace->root,
                            "esperava-se um diretório físico"));
    }
    auto removed = platform::remove_workspace(*workspace);
    if (!removed) {
        return std::unexpected(
            workspace_error("não foi possível remover o espaço de trabalho da transação",
                            workspace->root,
                            removed.error()));
    }
    auto synced = platform::durability::sync_parent_directory(workspace->root);
    if (!synced) {
        return std::unexpected(
            workspace_error("não foi possível sincronizar o diretório pai do espaço de trabalho da transação",
                            workspace->root.parent_path(),
                            synced.error()));
    }
    return {};
}

std::expected<void, Error> finish_transaction_cleanup(
    const journal::Paths& paths,
    const std::optional<platform::Workspace>& workspace) {
    auto removed = remove_transaction_workspace(workspace);
    if (!removed) {
        return std::unexpected(removed.error());
    }
    auto cleared = journal::clear(paths);
    if (!cleared) {
        return std::unexpected(journal_error(cleared.error()));
    }
    return {};
}

std::expected<void, Error>
cleanup_orphan_workspaces(const std::filesystem::path& profile) {
    auto directory = transactions_directory(profile, false);
    if (!directory) {
        return std::unexpected(directory.error());
    }
    auto status = read_status(*directory);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (missing(*status)) {
        return {};
    }
    if (std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_directory(*status)) {
        return std::unexpected(
            workspace_error("diretório de transações inválido",
                            *directory,
                            "esperava-se um diretório físico"));
    }

    std::vector<std::filesystem::path> candidates;
    std::error_code error;
    {
        std::filesystem::directory_iterator entry(*directory, error);
        if (error) {
            return std::unexpected(
                workspace_error("não foi possível enumerar os espaços de trabalho de transação",
                                *directory,
                                error.message()));
        }
        const std::filesystem::directory_iterator end;
        while (entry != end) {
            const auto candidate = entry->path().lexically_normal();
            const auto name = platform::path::to_utf8(candidate.filename());
            if (transaction::valid_transaction_id(name)) {
                if (candidate.parent_path() != directory->lexically_normal()) {
                    return std::unexpected(
                        workspace_error("caminho inseguro de espaço de trabalho de transação",
                                        candidate,
                                        "o caminho escapa do diretório de transações"));
                }
                const auto child_status =
                    std::filesystem::symlink_status(candidate, error);
                if (error) {
                    return std::unexpected(workspace_error(
                        "não foi possível inspecionar o espaço de trabalho da transação",
                        candidate,
                        error.message()));
                }
                if (std::filesystem::is_symlink(child_status) ||
                    !std::filesystem::is_directory(child_status)) {
                    return std::unexpected(
                        workspace_error("espaço de trabalho de transação inválido",
                                        candidate,
                                        "esperava-se um diretório físico"));
                }
                candidates.push_back(candidate);
            }
            entry.increment(error);
            if (error) {
                return std::unexpected(workspace_error(
                    "não foi possível enumerar os espaços de trabalho de transação",
                    *directory,
                    error.message()));
            }
        }
    }
    std::ranges::sort(candidates);
    for (const auto& candidate : candidates) {
        auto removed = remove_transaction_workspace(
            platform::Workspace{.root = candidate});
        if (!removed) {
            return std::unexpected(removed.error());
        }
    }
    return {};
}

std::expected<journal::Paths, Error>
make_journal_paths(const runtime::RuntimeData& runtime_data) {
    auto profile = profile_directory(runtime_data);
    if (!profile) {
        return std::unexpected(profile.error());
    }
    auto paths = journal::make_paths(*profile);
    if (!paths) {
        return std::unexpected(journal_error(paths.error()));
    }
    return *paths;
}

std::expected<void, Error>
save_record(const journal::Paths& paths,
            const transaction::Record& record,
            std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    const auto trace = platform::perf_trace::begin();
    auto saved = journal::save(paths, record, key);
    if (trace.active) {
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - trace.started)
                .count();
        platform::perf_trace::maximum(
            "journal save maximum us",
            static_cast<std::uint64_t>(std::max<std::int64_t>(elapsed, 0)));
    }
    platform::perf_trace::finish("journal save", trace);
    const char* phase_metric = nullptr;
    switch (record.phase) {
        case transaction::Phase::CommitUploaded:
            phase_metric = "journal CommitUploaded save";
            break;
        case transaction::Phase::CommitVerified:
            phase_metric = "journal CommitVerified save";
            break;
        case transaction::Phase::HeadPublished:
            phase_metric = "journal HeadPublished save";
            break;
        case transaction::Phase::HeadVerified:
            phase_metric = "journal HeadVerified save";
            break;
        default:
            break;
    }
    if (phase_metric != nullptr) {
        platform::perf_trace::finish(phase_metric, trace);
    }
    if (!saved) {
        return std::unexpected(journal_error(saved.error()));
    }
    return {};
}

history_storage::epoch::Epoch genesis_epoch(const transaction::Record& record) {
    return {
        .vault_id = record.epoch_vault_id,
        .sequence = 0,
        .issued_at = record.epoch_issued_at,
        .policy = {.min_history_depth = record.epoch_min_history_depth,
                   .min_history_age_hours = record.epoch_min_history_age_hours},
        .anchors = {{.commit_id = record.commit_id, .height = 0}},
        .previous_epoch_id = {}};
}

std::expected<history_storage::epoch::SealedEpoch, Error>
prepare_genesis_epoch(transaction::Record& record,
                      history_storage::epoch::RetentionPolicy policy,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (record.plan.target_generation != 0 || !record.parent_ids.empty()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput, "commit não é genesis"));
    }
    if (record.epoch_vault_id.empty()) {
        auto vault_id = platform::random::hex_id(HASH_SIZE);
        auto issued_at = platform::clock::unix_seconds();
        if (!vault_id || !issued_at) {
            return std::unexpected(
                make_error(ErrorCode::WorkspaceFailure,
                           vault_id ? issued_at.error() : vault_id.error()));
        }
        record.epoch_vault_id = std::move(*vault_id);
        record.epoch_issued_at = *issued_at;
        record.epoch_min_history_depth = policy.min_history_depth;
        record.epoch_min_history_age_hours = policy.min_history_age_hours;
    }
    auto sealed = history_storage::epoch::seal(genesis_epoch(record), key);
    if (!sealed) {
        return std::unexpected(
            make_error(ErrorCode::PublicationFailure, sealed.error().detail));
    }
    if (!record.epoch_id.empty() &&
        record.epoch_id != sealed->reference.epoch_id) {
        return std::unexpected(make_error(ErrorCode::RecoveryConflict,
                                          "Epoch genesis do journal diverge"));
    }
    record.epoch_id = sealed->reference.epoch_id;
    return *sealed;
}

std::expected<history_storage::epoch::SealedEpoch, Error>
prepare_pruning_epoch(transaction::Record& record,
                      history_storage::epoch::RetentionPolicy policy,
                      const history_storage::epoch::EpochPlan& plan,
                      const std::string& previous_vault_id,
                      std::uint64_t previous_sequence,
                      const std::string& previous_epoch_id,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (previous_sequence == std::numeric_limits<std::uint64_t>::max()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput,
                       "Epoch sequence cannot advance beyond uint64 maximum"));
    }
    if (record.epoch_vault_id.empty()) {
        record.epoch_vault_id = previous_vault_id;
        auto issued_at = platform::clock::unix_seconds();
        if (!issued_at) {
            return std::unexpected(
                make_error(ErrorCode::WorkspaceFailure, issued_at.error()));
        }
        record.epoch_issued_at = *issued_at;
        record.epoch_min_history_depth = policy.min_history_depth;
        record.epoch_min_history_age_hours = policy.min_history_age_hours;
    }
    history_storage::epoch::Epoch epoch = {.vault_id = previous_vault_id,
                                           .sequence = previous_sequence + 1,
                                           .issued_at = record.epoch_issued_at,
                                           .policy = policy,
                                           .anchors = plan.anchors,
                                           .previous_epoch_id =
                                               previous_epoch_id};
    auto sealed = history_storage::epoch::seal(epoch, key);
    if (!sealed) {
        return std::unexpected(
            make_error(ErrorCode::PublicationFailure, sealed.error().detail));
    }
    if (!record.epoch_id.empty() &&
        record.epoch_id != sealed->reference.epoch_id) {
        return std::unexpected(make_error(ErrorCode::RecoveryConflict,
                                          "Epoch do journal diverge"));
    }
    record.epoch_id = sealed->reference.epoch_id;
    return *sealed;
}

static std::expected<std::optional<history_storage::epoch::Reference>, Error>
epoch_reference_for_state(
    const reconciliation::StorageState& observed,
    const std::optional<history_storage::epoch::Reference>&
        verified_new_epoch) {
    // state.db stores only the last authenticated Epoch; the identity in the
    // journal represents progress and may still name an unaccepted
    // candidate.
    if (verified_new_epoch) {
        return verified_new_epoch;
    }
    if (observed.epoch_id.empty()) {
        return std::optional<history_storage::epoch::Reference>{};
    }
    return history_storage::epoch::Reference{
        .sequence = observed.epoch_sequence, .epoch_id = observed.epoch_id};
}

std::expected<void, Error>
validate_epoch_policy_presence(const reconciliation::StorageState& observed) {
    if (observed.epoch_id.empty()) {
        if (!observed.epoch_vault_id.empty() || observed.epoch_sequence != 0 ||
            observed.epoch_policy) {
            return std::unexpected(make_error(
                ErrorCode::InvalidInput,
                "estado de Epoch parcial sem uma identidade autenticada"));
        }
        return {};
    }
    if (!history::valid_commit_id(observed.epoch_id) ||
        !history::valid_commit_id(observed.epoch_vault_id) ||
        !observed.epoch_policy ||
        observed.epoch_policy->min_history_depth == 0 ||
        observed.epoch_policy->min_history_depth >
            history::maximum_graph_depth ||
        observed.epoch_policy->min_history_age_hours == 0) {
        return std::unexpected(make_error(
            ErrorCode::InvalidInput,
            "estado de Epoch autenticado é estruturalmente inválido"));
    }
    return {};
}

std::expected<history_storage::epoch::RetentionPolicy, Error>
authenticated_epoch_policy(const reconciliation::StorageState& observed) {
    if (observed.epoch_id.empty() || observed.epoch_vault_id.empty() ||
        !observed.epoch_policy) {
        return std::unexpected(
            detail::make_error(ErrorCode::InvalidInput,
                               "authenticated remote Epoch policy is missing"));
    }
    if (observed.epoch_policy->min_history_depth == 0 ||
        observed.epoch_policy->min_history_depth >
            history::maximum_graph_depth ||
        observed.epoch_policy->min_history_age_hours == 0) {
        return std::unexpected(
            detail::make_error(ErrorCode::InvalidInput,
                               "authenticated remote Epoch policy is invalid"));
    }
    return history_storage::epoch::RetentionPolicy{
        .min_history_depth = observed.epoch_policy->min_history_depth,
        .min_history_age_hours = observed.epoch_policy->min_history_age_hours};
}

bool same_epoch_frontier(
    std::span<const reconciliation::EpochAnchor> accepted,
    std::span<const history_storage::epoch::Anchor> planned) noexcept {
    return std::ranges::equal(
        accepted, planned, [](const auto& left, const auto& right) {
            return left.commit_id == right.commit_id &&
                   left.height == right.height;
        });
}

transaction::Record
make_upload_batch_checkpoint(const transaction::Record& original,
                             const mutation::StagedUploadBatch& batch) {
    transaction::Record checkpoint = original;
    for (const auto& obj : batch.objects) {
        for (std::size_t index : obj.operation_indices) {
            checkpoint.progress[index].state =
                transaction::OperationState::Applied;
        }
    }
    return checkpoint;
}

std::expected<void, Error>
checkpoint_upload_batch(const journal::Paths& paths,
                        transaction::Record& record,
                        const mutation::StagedUploadBatch& batch,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    auto checkpoint = make_upload_batch_checkpoint(record, batch);
    auto saved = save_record(paths, checkpoint, key);
    if (!saved) {
        return std::unexpected(saved.error());
    }

    record = std::move(checkpoint);

    return {};
}

std::expected<void, Error>
rollback_transaction(const journal::Paths& paths,
                     transaction::Record& record,
                     const std::optional<platform::Workspace>& workspace,
                     const std::filesystem::path& local_root,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (workspace) {
        for (std::size_t index = record.plan.operations.size(); index > 0;
             --index) {
            const auto operation_index = index - 1;
            const auto& progress = record.progress[operation_index];
            if (progress.state < transaction::OperationState::BackupCreated) {
                continue;
            }
            auto rolled = mutation::rollback_operation(
                record.plan.operations[operation_index],
                operation_index,
                local_root,
                *workspace,
                progress);
            if (!rolled) {
                return std::unexpected(make_error(
                    ErrorCode::RecoveryConflict,
                    "rollback failed: " + mutation::describe(rolled.error()),
                    operation_index));
            }
        }
    }
    record.phase = transaction::Phase::Started;
    record.commit_id.clear();
    record.ciphertext_id.clear();
    record.parent_ids.clear();
    record.marker_id.clear();
    record.epoch_vault_id.clear();
    record.epoch_id.clear();
    record.epoch_issued_at = 0;
    record.epoch_min_history_depth = 0;
    record.epoch_min_history_age_hours = 0;
    for (auto& progress : record.progress) {
        progress.previous_hash.clear();
        progress.state = transaction::OperationState::Pending;
        progress.had_original = false;
    }
    auto saved = save_record(paths, record, key);
    if (!saved) {
        return std::unexpected(saved.error());
    }
    return finish_transaction_cleanup(paths, workspace);
}

std::expected<void, Error>
rollback_local_mutations(transaction::Record& record,
                         const std::optional<platform::Workspace>& workspace,
                         const std::filesystem::path& local_root) {
    if (!workspace) {
        return {};
    }
    for (std::size_t index = record.plan.operations.size(); index > 0;
         --index) {
        const auto operation_index = index - 1;
        if (!is_local_mutation(
                record.plan.operations[operation_index].action) ||
            record.progress[operation_index].state <
                transaction::OperationState::BackupCreated) {
            continue;
        }
        auto rolled = mutation::rollback_operation(
            record.plan.operations[operation_index],
            operation_index,
            local_root,
            *workspace,
            record.progress[operation_index]);
        if (!rolled) {
            return std::unexpected(make_error(
                ErrorCode::RecoveryConflict,
                "rollback local failed: " + mutation::describe(rolled.error()),
                operation_index));
        }
        record.progress[operation_index].state =
            transaction::OperationState::Prepared;
    }
    record.phase = transaction::Phase::FilesStaged;
    return {};
}

constexpr std::size_t default_content_concurrency = 8;
constexpr std::size_t maximum_experimental_content_concurrency = 16;

std::size_t content_concurrency() noexcept {
    const char* setting = std::getenv("KASUMI_CONTENT_CONCURRENCY");
    if (setting == nullptr) {
        return default_content_concurrency;
    }
    const std::string_view text{setting};
    unsigned value = 0;
    const auto parsed =
        std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        value == 0) {
        return default_content_concurrency;
    }
    return std::min<std::size_t>(value,
                                 maximum_experimental_content_concurrency);
}

} // namespace detail

namespace {

Error mutation_error(const mutation::MutationError& error) {
    return detail::make_error(ErrorCode::MutationFailure,
                              mutation::describe(error),
                              error.operation_index);
}

Error publication_error(const publication::Error& error) {
    return detail::make_error(ErrorCode::PublicationFailure, error.detail);
}

struct CommitTimeDecision {
    std::int64_t created_at = 0;
    bool pruning_time_safe = true;
};

std::expected<CommitTimeDecision, Error>
choose_commit_time(const reconciliation::StorageState& storage,
                   std::int64_t local_now) {
    if (local_now <= 0) {
        return std::unexpected(detail::make_error(
            ErrorCode::PublicationFailure, "invalid local commit timestamp"));
    }
    if (!storage.history_present) {
        return CommitTimeDecision{.created_at = local_now,
                                  .pruning_time_safe = true};
    }
    if (storage.logical_heads.empty()) {
        return std::unexpected(detail::make_error(
            ErrorCode::InvalidInput, "history has no logical heads"));
    }

    std::int64_t newest_parent = 0;
    for (const auto& head : storage.logical_heads) {
        const auto found = std::ranges::find(
            storage.reachable_commits, head, &history::LoadedCommit::id);
        if (found == storage.reachable_commits.end()) {
            return std::unexpected(detail::make_error(
                ErrorCode::InvalidInput,
                "logical head is missing from reachable commits"));
        }
        newest_parent = std::max(newest_parent, found->commit.created_at);
    }

    return CommitTimeDecision{.created_at = std::max(local_now, newest_parent),
                              .pruning_time_safe = newest_parent <= local_now};
}

} // namespace

namespace {

struct ContentWorkResult {
    std::size_t index = 0;
    std::optional<mutation::MutationError> error;
};

struct ContentWindowState {
    std::mutex mutex;
    std::condition_variable_any changed;
    std::vector<std::optional<std::size_t>> tasks;
    std::vector<std::optional<ContentWorkResult>> completions;
    std::size_t in_flight = 0;
    std::size_t peak_in_flight = 0;
};

void run_content_worker(std::stop_token stop,
                        std::size_t slot,
                        ContentWindowState& state,
                        const transaction::Record& record,
                        const std::filesystem::path& local_root,
                        transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const platform::Workspace& workspace) {
    while (!stop.stop_requested()) {
        std::size_t index = 0;
        {
            std::unique_lock lock(state.mutex);
            if (!state.changed.wait(lock, stop, [&] {
                    return state.tasks[slot].has_value();
                })) {
                return;
            }
            index = *state.tasks[slot];
            state.tasks[slot].reset();
            ++state.in_flight;
            state.peak_in_flight =
                std::max(state.peak_in_flight, state.in_flight);
        }

        ContentWorkResult result{.index = index, .error = std::nullopt};
        try {
            auto applied =
                mutation::apply_operation(record.plan.operations[index],
                                          index,
                                          local_root,
                                          storage,
                                          key,
                                          workspace);
            if (!applied) {
                result.error = applied.error();
            }
        } catch (const std::exception& exception) {
            result.error = mutation::MutationError{
                .code = mutation::MutationErrorCode::LocalIo,
                .detail =
                    std::string{"content worker failed: "} + exception.what(),
                .path = record.plan.operations[index].path,
                .operation_index = index};
        } catch (...) {
            result.error = mutation::MutationError{
                .code = mutation::MutationErrorCode::LocalIo,
                .detail = "content worker failed",
                .path = record.plan.operations[index].path,
                .operation_index = index};
        }

        {
            std::lock_guard lock(state.mutex);
            --state.in_flight;
            state.completions[slot] = std::move(result);
        }
        state.changed.notify_all();
    }
}

std::expected<std::optional<std::pair<std::size_t, mutation::MutationError>>,
              Error>
run_content_window(std::span<const std::size_t> indices,
                   std::size_t parallelism,
                   transaction::Record& record,
                   const journal::Paths& paths,
                   const std::filesystem::path& local_root,
                   transport::Transport& storage,
                   std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                   const platform::Workspace& workspace) {
    const auto worker_count = std::min(parallelism, indices.size());
    ContentWindowState state;
    state.tasks.resize(worker_count);
    state.completions.resize(worker_count);
    std::vector<std::jthread> workers;
    try {
        workers.reserve(worker_count);
        for (std::size_t slot = 0; slot < worker_count; ++slot) {
            workers.emplace_back(run_content_worker,
                                 slot,
                                 std::ref(state),
                                 std::cref(record),
                                 std::cref(local_root),
                                 std::ref(storage),
                                 key,
                                 std::cref(workspace));
        }
    } catch (const std::exception& exception) {
        return std::unexpected(detail::make_error(
            ErrorCode::MutationFailure,
            std::string{"não foi possível iniciar o worker de conteúdo: "} + exception.what(),
            indices.front()));
    }

    std::size_t next = 0;
    std::size_t outstanding = 0;
    const auto admit = [&](std::size_t slot) {
        {
            std::lock_guard lock(state.mutex);
            state.tasks[slot] = indices[next++];
            ++outstanding;
        }
        state.changed.notify_all();
    };
    for (std::size_t slot = 0; slot < worker_count; ++slot) {
        admit(slot);
    }

    std::optional<std::pair<std::size_t, mutation::MutationError>> failure;
    std::optional<Error> checkpoint_failure;
    while (outstanding != 0) {
        std::size_t slot = 0;
        ContentWorkResult result;
        {
            std::unique_lock lock(state.mutex);
            state.changed.wait(lock, [&] {
                return std::ranges::any_of(state.completions,
                                           [](const auto& item) {
                                               return item.has_value();
                                           });
            });
            auto completed =
                std::ranges::find_if(state.completions, [](const auto& item) {
                    return item && item->error.has_value();
                });
            if (completed == state.completions.end()) {
                completed = std::ranges::find_if(state.completions,
                                                 [](const auto& item) {
                                                     return item.has_value();
                                                 });
            }
            slot =
                static_cast<std::size_t>(completed - state.completions.begin());
            result = std::move(**completed);
            completed->reset();
        }
        --outstanding;
        platform::perf_trace::count("content completion count");

        if (result.error) {
            if (!failure) {
                failure = std::pair{result.index, std::move(*result.error)};
            }
        } else {
            record.progress[result.index].state =
                transaction::OperationState::Applied;
            auto saved = detail::save_record(paths, record, key);
            if (!saved && !checkpoint_failure) {
                checkpoint_failure = saved.error();
            }
        }

        if (!failure && !checkpoint_failure && next < indices.size()) {
            admit(slot);
        }
    }

    platform::perf_trace::maximum("content peak in-flight",
                                  state.peak_in_flight);
    if (checkpoint_failure) {
        return std::unexpected(std::move(*checkpoint_failure));
    }
    return failure;
}

bool same_operation(const Operation& left, const Operation& right) noexcept {
    return left.action == right.action && left.path == right.path &&
           left.hash == right.hash && left.alt_path == right.alt_path &&
           left.size == right.size &&
           left.exclusive_destination == right.exclusive_destination;
}

bool same_plan(const SyncPlan& left, const SyncPlan& right) noexcept {
    if (left.target_generation != right.target_generation ||
        left.offsets != right.offsets ||
        left.operations.size() != right.operations.size()) {
        return false;
    }
    return std::ranges::equal(
        left.operations, right.operations, same_operation);
}

bool same_rows(std::span<const NodeRow> left,
               std::span<const NodeRow> right) noexcept {
    return std::ranges::equal(left, right);
}

bool is_storage_repair_operation(const reconciliation::Input& input,
                                 const reconciliation::Result& result,
                                 const Operation& operation) noexcept {
    if (!result.requires_storage_repair || operation.action != Action::Upload ||
        !input.storage.history_present) {
        return false;
    }
    const auto expected_hash = hash_from_hex(operation.hash);
    const auto row =
        find_row(input.storage.tree, platform::path::to_logical_utf8(operation.path));
    return expected_hash.has_value() && row != nullptr && !row->is_directory &&
           row->hash == *expected_hash && row->size == operation.size;
}

std::vector<bool> required_content_uploads(const reconciliation::Input& input,
                                           const reconciliation::Result& result,
                                           const SyncPlan& plan) {
    std::unordered_set<std::string> available;
    if (input.storage.history_present) {
        for (const auto& row : input.storage.tree.rows) {
            if (!row.is_directory &&
                !result.missing_objects.contains(row.hash)) {
                available.insert(hash_hex(row.hash) + ':' +
                                 std::to_string(row.size));
            }
        }
    }

    std::vector<bool> required(plan.operations.size(), true);
    for (std::size_t index = 0; index < plan.operations.size(); ++index) {
        const auto& operation = plan.operations[index];
        if (operation.action != Action::Upload) {
            continue;
        }
        required[index] =
            available
                .insert(operation.hash + ':' + std::to_string(operation.size))
                .second;
    }
    return required;
}

std::expected<void, Error>
restore_transaction_metadata(const Snapshot& expected_tree,
                             const Snapshot& observed_tree,
                             const transaction::Record& record,
                             const std::filesystem::path& local_dir) {
    auto operation_paths = ::kasumi::application::sync::metadata_restore_paths(
        record, expected_tree);
    if (!operation_paths) {
        return std::unexpected(detail::make_error(ErrorCode::MutationFailure,
                                                  operation_paths.error()));
    }
    auto paths = ::kasumi::application::sync::metadata_restore_paths(
        record, expected_tree, &observed_tree);
    if (!paths) {
        return std::unexpected(
            detail::make_error(ErrorCode::MutationFailure, paths.error()));
    }
    for (const auto& path_name : *paths) {
        const auto* row = find_row(expected_tree, path_name);
        if (row == nullptr) {
            continue;
        }
        std::error_code error;
        auto path = row->path.empty()
                        ? local_dir
                        : local_dir / platform::path::from_utf8(row->path);
        const auto status = std::filesystem::symlink_status(path, error);
        if (error) {
            return std::unexpected(detail::make_error(
                ErrorCode::MutationFailure,
                "não foi possível restaurar o timestamp materializado para " + path_name +
                    ": " + error.message()));
        }
        if (std::filesystem::is_symlink(status) ||
            (row->is_directory ? !std::filesystem::is_directory(status)
                               : !std::filesystem::is_regular_file(status))) {
            return std::unexpected(detail::make_error(
                ErrorCode::MutationFailure,
                "não foi possível restaurar o timestamp materializado para " + path_name +
                    ": tipo de sistema de arquivos inesperado"));
        }
        const auto observed_only =
            std::ranges::find(*operation_paths, path_name) ==
            operation_paths->end();
        if (observed_only) {
            const auto* observed = find_row(observed_tree, path_name);
            const auto current = std::filesystem::last_write_time(path, error);
            if (error) {
                return std::unexpected(detail::make_error(
                    ErrorCode::MutationFailure,
                    "não foi possível confirmar o timestamp observado para " + path_name +
                        ": " + error.message()));
            }
            if (observed == nullptr || current != observed->mtime) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ConcurrentModification,
                    "diretório alterado após a observação: " + path_name));
            }
        }
        auto written =
            ::kasumi::platform::metadata::set_last_write_time(path, row->mtime);
        if (!written) {
            return std::unexpected(detail::make_error(
                ErrorCode::MutationFailure,
                "não foi possível restaurar o timestamp materializado para " + path_name +
                    ": " + written.error()));
        }
    }
    return {};
}

bool same_result(const reconciliation::Result& left,
                 const reconciliation::Result& right) noexcept {
    return same_plan(left.plan, right.plan) &&
           left.missing_objects == right.missing_objects &&
           same_rows(left.pending_storage_rows, right.pending_storage_rows) &&
           left.unrecoverable_paths == right.unrecoverable_paths &&
           left.observed_storage_generation ==
               right.observed_storage_generation &&
           left.target_generation == right.target_generation &&
           left.recovering_missing_history ==
               right.recovering_missing_history &&
           left.has_conflicts == right.has_conflicts &&
           left.requires_local_mutation == right.requires_local_mutation &&
           left.requires_storage_repair == right.requires_storage_repair &&
           same_rows(left.candidate_shared_tree.rows,
                     right.candidate_shared_tree.rows) &&
           left.shared_tree_changed == right.shared_tree_changed &&
           left.requires_publication == right.requires_publication &&
           left.requires_state_commit == right.requires_state_commit;
}

std::expected<void, Error>
validate_execution_composition(const reconciliation::Input& input,
                               const reconciliation::Result& result) {
    auto expected = reconciliation::reconcile(input);
    if (!expected) {
        return std::unexpected(detail::make_error(
            ErrorCode::CompositionMismatch,
            "input cannot reproduce result: " + expected.error().detail));
    }
    if (!same_result(*expected, result)) {
        return std::unexpected(
            detail::make_error(ErrorCode::CompositionMismatch,
                               "reconciliation input and result do not match"));
    }
    return {};
}

} // namespace

std::string describe(const Error& error) {
    std::string result;
    switch (error.code) {
        case ErrorCode::InvalidInput:
            result = "invalid_input";
            break;
        case ErrorCode::JournalFailure:
            result = "journal_failure";
            break;
        case ErrorCode::WorkspaceFailure:
            result = "workspace_failure";
            break;
        case ErrorCode::MutationFailure:
            result = "mutation_failure";
            break;
        case ErrorCode::PublicationFailure:
            result = "publication_failure";
            break;
        case ErrorCode::DatabaseFailure:
            result = "database_failure";
            break;
        case ErrorCode::CompositionMismatch:
            result = "composition_mismatch";
            break;
        case ErrorCode::ObservationFailure:
            result = "observation_failure";
            break;
        case ErrorCode::ConcurrentModification:
            result = "concurrent_modification";
            break;
        case ErrorCode::RecoveryIndeterminate:
            result = "recovery_indeterminate";
            break;
        case ErrorCode::RecoveryConflict:
            result = "recovery_conflict";
            break;
        case ErrorCode::RecoveryRequired:
            result = "recovery_required";
            break;
    }
    if (error.operation_index) {
        result += " operation " + std::to_string(*error.operation_index);
    }
    if (!error.detail.empty()) {
        result += ": " + error.detail;
    }
    return result;
}

bool same_plan_operations(const SyncPlan& left, const SyncPlan& right) noexcept {
    if (left.operations.size() != right.operations.size()) {
        return false;
    }
    for (std::size_t i = 0; i < left.operations.size(); ++i) {
        const auto& a = left.operations[i];
        const auto& b = right.operations[i];
        if (a.action != b.action || a.path != b.path || a.hash != b.hash ||
            a.size != b.size || a.alt_path != b.alt_path ||
            a.exclusive_destination != b.exclusive_destination) {
            return false;
        }
    }
    return true;
}

std::expected<void, Error>
execute(const runtime::RuntimeData& runtime_data,
        transport::Transport& storage,
        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
        const reconciliation::Input& observed_input,
        const reconciliation::Result& reconciliation_result,
        observation::LocalObservationSession* session) {
    if (runtime_data.local_dir.empty() || runtime_data.database_path.empty() ||
        !transport::valid(storage) ||
        !reconciliation::has_safe_paths(reconciliation_result.plan)) {
        return std::unexpected(detail::make_error(ErrorCode::InvalidInput,
                                                  "invalid transaction input"));
    }

    auto composition =
        validate_execution_composition(observed_input, reconciliation_result);
    if (!composition) {
        return std::unexpected(composition.error());
    }
    auto epoch_policy_presence =
        detail::validate_epoch_policy_presence(observed_input.storage);
    if (!epoch_policy_presence) {
        return std::unexpected(epoch_policy_presence.error());
    }

    auto paths = detail::make_journal_paths(runtime_data);
    if (!paths) {
        return std::unexpected(paths.error());
    }
    journal::discard_temporary(*paths);
    auto existing = journal::load(*paths, key);
    if (!existing) {
        return std::unexpected(detail::journal_error(existing.error()));
    }
    auto profile = detail::profile_directory(runtime_data);
    if (!profile) {
        return std::unexpected(profile.error());
    }
    std::string observed_head_id;
    if (!reconciliation_result.requires_publication) {
        if (observed_input.storage.logical_heads.size() != 1) {
            return std::unexpected(detail::make_error(
                ErrorCode::InvalidInput,
                "local-only execution requires exactly one logical head"));
        }
        observed_head_id = observed_input.storage.logical_heads.front();
    }

    std::optional<transaction::Record> record_storage;
    if (*existing) {
        if ((*existing)->publication_required ==
                reconciliation_result.requires_publication &&
            (*existing)->local_generation == observed_input.local_generation &&
            (*existing)->storage_generation ==
                observed_input.storage.generation &&
            same_plan_operations((*existing)->plan, reconciliation_result.plan)) {
            record_storage = std::move(**existing);
        } else {
            return std::unexpected(detail::make_error(
                ErrorCode::RecoveryRequired, "pending transaction exists"));
        }
    } else {
        auto record =
            journal::create_record(observed_input.local_generation,
                                   observed_input.storage.generation,
                                   reconciliation_result.plan,
                                   reconciliation_result.requires_publication,
                                   std::move(observed_head_id));
        if (!record) {
            return std::unexpected(detail::journal_error(record.error()));
        }
        record_storage = std::move(*record);
    }
    auto& record = record_storage;
    const auto content_upload_required = required_content_uploads(
        observed_input, reconciliation_result, record->plan);
    for (const auto& operation : record->plan.operations) {
        platform::perf_trace::count(
            detail::action_metrics[action_index(operation.action)]);
    }
    auto saved = detail::save_record(*paths, *record, key);
    if (!saved) {
        return std::unexpected(saved.error());
    }
    auto workspace =
        detail::create_transaction_workspace(*profile, record->operation_id);
    if (!workspace) {
        return std::unexpected(workspace.error());
    }
    std::optional<platform::Workspace> transaction_workspace{*workspace};

    for (std::size_t index = 0; index < record->plan.operations.size();
         ++index) {
        auto prepared =
            mutation::prepare_operation(record->plan.operations[index],
                                        index,
                                        runtime_data.local_dir,
                                        *workspace,
                                        record->progress[index]);
        if (!prepared) {
            auto rolled = detail::rollback_transaction(*paths,
                                                       *record,
                                                       transaction_workspace,
                                                       runtime_data.local_dir,
                                                       key);
            if (!rolled)
                return std::unexpected(rolled.error());
            return std::unexpected(mutation_error(prepared.error()));
        }
        record->progress[index] = *prepared;
        if (is_logical_mutation(record->plan.operations[index].action) ||
            !content_upload_required[index]) {
            continue;
        }
        saved = detail::save_record(*paths, *record, key);
        if (!saved) {
            return std::unexpected(saved.error());
        }
    }
    record->phase = transaction::Phase::FilesStaged;
    saved = detail::save_record(*paths, *record, key);
    if (!saved)
        return std::unexpected(saved.error());

    const auto rollback_terminal = [&]() {
        return detail::rollback_transaction(*paths,
                                            *record,
                                            transaction_workspace,
                                            runtime_data.local_dir,
                                            key);
    };

    std::optional<publication::PreparedCommit> prepared_commit;
    std::optional<CommitTimeDecision> commit_time;
    // Destroyed first: waits for the task before destroying prepared_commit.
    std::future<publication::PublishObjectResult> commit_publication;
    if (record->publication_required) {
        const auto local_now = platform::clock::unix_seconds();
        if (!local_now || *local_now <= 0) {
            auto rolled = rollback_terminal();
            if (!rolled)
                return std::unexpected(rolled.error());
            return std::unexpected(detail::make_error(
                ErrorCode::PublicationFailure,
                local_now ? "timestamp de commit local inválido"
                          : "não foi possível ler o timestamp do commit local: " +
                                local_now.error()));
        }
        auto chosen_time =
            choose_commit_time(observed_input.storage, *local_now);
        if (!chosen_time) {
            auto rolled = rollback_terminal();
            if (!rolled)
                return std::unexpected(rolled.error());
            return std::unexpected(chosen_time.error());
        }
        commit_time.emplace(*chosen_time);
        auto prepared = publication::prepare_commit(
            reconciliation_result.candidate_shared_tree,
            observed_input.storage.history_present,
            observed_input.storage.generation,
            observed_input.storage.logical_heads,
            commit_time->created_at,
            key);
        if (!prepared) {
            auto rolled = rollback_terminal();
            if (!rolled)
                return std::unexpected(rolled.error());
            return std::unexpected(publication_error(prepared.error()));
        }
        prepared_commit.emplace(std::move(*prepared));

        const auto publication_workspace =
            runtime_data.database_path.parent_path();
        try {
            commit_publication = std::async(
                std::launch::async,
                [&storage,
                 key,
                 publication_workspace,
                 prepared = &*prepared_commit]() {
                    const auto commit_put_trace = platform::perf_trace::begin();
                    auto published = publication::publish_commit_object(
                        storage, key, *prepared, publication_workspace);
                    platform::perf_trace::finish("commit PUT",
                                                 commit_put_trace);
                    if (!published)
                        return published;
                    const auto commit_verification_trace =
                        platform::perf_trace::begin();
                    auto verified = publication::verify_commit_object(
                        storage,
                        key,
                        *prepared,
                        published->head,
                        publication_workspace,
                        published->physical_hash);
                    platform::perf_trace::finish("commit verification",
                                                 commit_verification_trace);
                    if (!verified) {
                        return publication::PublishObjectResult{
                            std::unexpected(verified.error())};
                    }
                    return published;
                });
        } catch (const std::exception& exception) {
            auto rolled = rollback_terminal();
            if (!rolled)
                return std::unexpected(rolled.error());
            return std::unexpected(detail::make_error(
                ErrorCode::PublicationFailure,
                std::string{"não foi possível iniciar o envio do commit: "} +
                    exception.what()));
        }
        platform::perf_trace::count("speculative commit uploads");
    }

    std::vector<std::size_t> apply_order;
    apply_order.reserve(record->plan.operations.size());
    if (!record->publication_required &&
        reconciliation_result.requires_storage_repair) {
        for (std::size_t index = 0; index < record->plan.operations.size();
             ++index) {
            if (content_upload_required[index] &&
                is_storage_repair_operation(observed_input,
                                            reconciliation_result,
                                            record->plan.operations[index])) {
                apply_order.push_back(index);
            }
        }
    }
    for (std::size_t index = 0; index < record->plan.operations.size();
         ++index) {
        if (!content_upload_required[index] ||
            record->progress[index].state ==
                transaction::OperationState::Applied) {
            record->progress[index].state =
                transaction::OperationState::Applied;
            platform::perf_trace::count("content uploads elided");
            continue;
        }
        if (std::ranges::find(apply_order, index) == apply_order.end()) {
            apply_order.push_back(index);
        }
    }

    const auto mark_applied =
        [&](std::size_t index) -> std::expected<void, Error> {
        record->progress[index].state = transaction::OperationState::Applied;
        if (is_logical_mutation(record->plan.operations[index].action)) {
            return {};
        }
        return detail::save_record(*paths, *record, key);
    };

    const auto has_applied_uploads = [&]() noexcept {
        return std::ranges::any_of(
            record->progress, [](const auto& p) {
                return p.state == transaction::OperationState::Applied;
            });
    };

    const auto fail_mutation = [&](std::size_t index,
                                   const mutation::MutationError& failure)
        -> std::expected<void, Error> {
        if (!record->publication_required &&
            is_storage_repair_operation(observed_input,
                                        reconciliation_result,
                                        record->plan.operations[index])) {
            return std::unexpected(mutation_error(failure));
        }
        if (record->publication_required &&
            record->phase <= transaction::Phase::CommitPrepared &&
            has_applied_uploads()) {
            if (transaction_workspace) {
                std::error_code ec;
                std::filesystem::remove_all(
                    transaction_workspace->root / "upload-batches", ec);
            }
            return std::unexpected(mutation_error(failure));
        }
        auto rolled = detail::rollback_transaction(*paths,
                                                   *record,
                                                   transaction_workspace,
                                                   runtime_data.local_dir,
                                                   key);
        if (!rolled) {
            return std::unexpected(rolled.error());
        }
        return std::unexpected(mutation_error(failure));
    };

    const auto parallelism = detail::content_concurrency();
    platform::perf_trace::maximum("configured content concurrency",
                                  parallelism);
    std::unordered_map<std::string, std::size_t> download_counts;
    for (const auto index : apply_order) {
        const auto& operation = record->plan.operations[index];
        if (operation.action == Action::Download) {
            ++download_counts[operation.hash + ':' +
                              std::to_string(operation.size)];
        }
    }
    std::unordered_set<std::string> populated_downloads;
    const auto content_transfer_trace = platform::perf_trace::begin();
    for (std::size_t position = 0; position < apply_order.size();) {
        const auto first = apply_order[position];
        const auto& first_operation = record->plan.operations[first];
        if (first_operation.action == Action::Download) {
            const auto content_key = first_operation.hash + ':' +
                                     std::to_string(first_operation.size);
            if (download_counts[content_key] == 1) {
                std::size_t end = position;
                while (end < apply_order.size()) {
                    const auto& operation =
                        record->plan.operations[apply_order[end]];
                    if (operation.action != Action::Download ||
                        download_counts[operation.hash + ':' +
                                        std::to_string(operation.size)] != 1) {
                        break;
                    }
                    ++end;
                }
                if (end != position + 1) {
                    auto failure = run_content_window(
                        std::span<const std::size_t>{apply_order}.subspan(
                            position, end - position),
                        parallelism,
                        *record,
                        *paths,
                        runtime_data.local_dir,
                        storage,
                        key,
                        *workspace);
                    if (!failure) {
                        platform::perf_trace::finish("content transfer wall",
                                                     content_transfer_trace);
                        return std::unexpected(failure.error());
                    }
                    if (*failure) {
                        platform::perf_trace::finish("content transfer wall",
                                                     content_transfer_trace);
                        return fail_mutation((*failure)->first,
                                             (*failure)->second);
                    }
                    position = end;
                    continue;
                }
            }
        }
        if (record->plan.operations[first].action != Action::Upload) {
            const auto& operation = first_operation;
            auto download_cache = mutation::DownloadCacheMode::None;
            if (operation.action == Action::Download) {
                const auto content_key =
                    operation.hash + ':' + std::to_string(operation.size);
                if (download_counts[content_key] > 1) {
                    download_cache =
                        populated_downloads.insert(content_key).second
                            ? mutation::DownloadCacheMode::Populate
                            : mutation::DownloadCacheMode::Reuse;
                }
            }
            auto applied =
                mutation::apply_operation(record->plan.operations[first],
                                          first,
                                          runtime_data.local_dir,
                                          storage,
                                          key,
                                          *workspace,
                                          download_cache);
            if (!applied) {
                platform::perf_trace::finish("content transfer wall",
                                             content_transfer_trace);
                return fail_mutation(first, applied.error());
            }
            auto marked = mark_applied(first);
            if (!marked) {
                platform::perf_trace::finish("content transfer wall",
                                             content_transfer_trace);
                return std::unexpected(marked.error());
            }
            ++position;
            continue;
        }

        std::size_t end = position;
        std::vector<std::size_t> pending_uploads;
        while (end < apply_order.size() &&
               record->plan.operations[apply_order[end]].action ==
                   Action::Upload) {
            const auto op_index = apply_order[end];
            if (record->progress[op_index].state !=
                transaction::OperationState::Applied) {
                pending_uploads.push_back(op_index);
            }
            ++end;
        }

        for (std::size_t chunk_start = 0; chunk_start < pending_uploads.size();) {
            std::vector<std::size_t> chunk;
            std::uint64_t chunk_bytes = 0;
            while (chunk_start + chunk.size() < pending_uploads.size() &&
                   chunk.size() < detail::upload_batch_max_items &&
                   (chunk.empty() ||
                    chunk_bytes +
                        record->plan.operations[pending_uploads[chunk_start + chunk.size()]].size <=
                        detail::upload_batch_max_bytes)) {
                const auto op_index = pending_uploads[chunk_start + chunk.size()];
                chunk_bytes += record->plan.operations[op_index].size;
                chunk.push_back(op_index);
            }
            chunk_start += chunk.size();

            const auto stage_trace = platform::perf_trace::begin();
            auto staged_batch = mutation::stage_upload_batch(
                chunk, *record, runtime_data.local_dir, key, *workspace);
            platform::perf_trace::finish("content stage", stage_trace);

            if (!staged_batch) {
                platform::perf_trace::finish("content transfer wall",
                                             content_transfer_trace);
                return fail_mutation(staged_batch.error().operation_index,
                                     staged_batch.error());
            }

            const auto transfer_trace = platform::perf_trace::begin();
            auto transferred = mutation::transfer_upload_batch(
                *staged_batch, storage, parallelism);
            platform::perf_trace::finish("content transfer", transfer_trace);

            const bool transfer_unknown =
                !transferred &&
                transferred.error().code ==
                    mutation::MutationErrorCode::RemoteResultUnknown;
            if (!transferred && !transfer_unknown) {
                platform::perf_trace::finish("content transfer wall",
                                             content_transfer_trace);
                return fail_mutation(transferred.error().operation_index,
                                     transferred.error());
            }

            const auto verification_trace = platform::perf_trace::begin();
            auto verified = mutation::verify_upload_batch(
                *staged_batch, storage, key, *workspace, parallelism);
            platform::perf_trace::finish("content verification wall",
                                         verification_trace);

            if (!verified) {
                platform::perf_trace::finish("content transfer wall",
                                             content_transfer_trace);
                if (transfer_unknown &&
                    verified.error().code ==
                        mutation::MutationErrorCode::TransportFailure) {
                    return std::unexpected(mutation_error(verified.error()));
                }
                return fail_mutation(verified.error().operation_index,
                                     verified.error());
            }

            const auto checkpoint_trace = platform::perf_trace::begin();
            auto checkpointed = detail::checkpoint_upload_batch(
                *paths, *record, *staged_batch, key);
            platform::perf_trace::finish("batch checkpoint", checkpoint_trace);

            if (!checkpointed) {
                platform::perf_trace::finish("content transfer wall",
                                             content_transfer_trace);
                return std::unexpected(checkpointed.error());
            }

            auto cleaned = mutation::cleanup_upload_batch(*staged_batch);

            if (!cleaned) {
                platform::perf_trace::finish("content transfer wall",
                                             content_transfer_trace);
                return std::unexpected(mutation_error(cleaned.error()));
            }
        }

        position = end;
    }
    platform::perf_trace::finish("content transfer wall",
                                 content_transfer_trace);
    record->phase = transaction::Phase::LocalChangesApplied;
    saved = detail::save_record(*paths, *record, key);
    if (!saved)
        return std::unexpected(saved.error());

    const auto& expected_tree =
        record->publication_required
            ? reconciliation_result.candidate_shared_tree
            : observed_input.storage.tree;
    auto timestamps = restore_transaction_metadata(expected_tree,
                                                   observed_input.local_tree,
                                                   *record,
                                                   runtime_data.local_dir);
    if (!timestamps) {
        auto rolled = rollback_terminal();
        if (!rolled)
            return std::unexpected(rolled.error());
        return std::unexpected(timestamps.error());
    }

    const auto final_scan_trace = platform::perf_trace::begin();
    auto scanned =
        observation::collect_local_tree(runtime_data.local_dir, session);
    platform::perf_trace::finish("final local validation", final_scan_trace);
    if (!scanned) {
        auto rolled = rollback_terminal();
        if (!rolled)
            return std::unexpected(rolled.error());
        return std::unexpected(detail::make_error(ErrorCode::MutationFailure,
                                                  "local scan failed"));
    }
    // Identifies new files or directories created locally and concurrently during sync.
    std::unordered_set<std::string> concurrent_new_paths;
    std::unordered_set<std::string> affected_ancestor_dirs;
    for (const auto& row : scanned->rows) {
        if (!row.path.empty() &&
            find_row(observed_input.local_tree, row.path) == nullptr &&
            find_row(reconciliation_result.candidate_shared_tree, row.path) == nullptr) {
            concurrent_new_paths.insert(row.path);
            for (auto parent = row_parent(row.path); !parent.empty();
                 parent = row_parent(parent)) {
                affected_ancestor_dirs.emplace(parent);
            }
            affected_ancestor_dirs.insert("");
        }
    }

    Snapshot validation_local_tree;
    if (concurrent_new_paths.empty()) {
        validation_local_tree = std::move(*scanned);
    } else {
        validation_local_tree.rows.reserve(scanned->rows.size());
        for (auto& row : scanned->rows) {
            if (concurrent_new_paths.contains(row.path)) {
                continue;
            }
            if (row.is_directory && affected_ancestor_dirs.contains(row.path)) {
                const auto* expected_dir =
                    find_row(reconciliation_result.candidate_shared_tree, row.path);
                if (expected_dir != nullptr) {
                    row.mtime = expected_dir->mtime;
                }
            }
            validation_local_tree.rows.push_back(std::move(row));
        }
        finalize_snapshot(validation_local_tree);
    }

    auto publication_tree = reconciliation::build_publication_tree(
        std::move(validation_local_tree),
        reconciliation_result.pending_storage_rows,
        reconciliation_result.candidate_shared_tree);
    if (!publication_tree) {
        auto rolled = rollback_terminal();
        if (!rolled)
            return std::unexpected(rolled.error());
        return std::unexpected(detail::make_error(
            ErrorCode::PublicationFailure, publication_tree.error().detail));
    }

    if (record->publication_required &&
        !same_rows(publication_tree->rows,
                   reconciliation_result.candidate_shared_tree.rows)) {
        auto rolled = rollback_terminal();
        if (!rolled)
            return std::unexpected(rolled.error());
        std::string detail_message = "a árvore materializada não corresponde à "
                                     "árvore candidata reconciliada";
        if (publication_tree->rows.size() !=
            reconciliation_result.candidate_shared_tree.rows.size()) {
            detail_message += " (linhas reais=" +
                              std::to_string(publication_tree->rows.size()) +
                              ", esperadas=" +
                              std::to_string(
                                  reconciliation_result.candidate_shared_tree.rows.size()) +
                              ")";
        }
        const auto count =
            std::min(publication_tree->rows.size(),
                     reconciliation_result.candidate_shared_tree.rows.size());
        std::size_t mismatch_index = count;
        for (std::size_t index = 0; index < count; ++index) {
            const auto& actual = publication_tree->rows[index];
            const auto& expected =
                reconciliation_result.candidate_shared_tree.rows[index];
            if (actual.path != expected.path ||
                actual.is_directory != expected.is_directory) {
                mismatch_index = index;
                break;
            }
            if (!actual.is_directory && !expected.is_directory) {
                if (actual.hash != expected.hash || actual.size != expected.size ||
                    actual.mtime != expected.mtime) {
                    mismatch_index = index;
                    break;
                }
            }
        }
        if (mismatch_index >= count) {
            if (publication_tree->rows.size() > count) {
                std::string added_file;
                for (std::size_t i = count; i < publication_tree->rows.size(); ++i) {
                    if (!publication_tree->rows[i].is_directory) {
                        added_file = publication_tree->rows[i].path;
                        break;
                    }
                }
                if (added_file.empty()) {
                    added_file = publication_tree->rows[count].path;
                }
                detail_message += " (arquivo adicionado no disco durante sync: " + added_file + ")";
            } else if (reconciliation_result.candidate_shared_tree.rows.size() > count) {
                std::string removed_file;
                for (std::size_t i = count; i < reconciliation_result.candidate_shared_tree.rows.size(); ++i) {
                    if (!reconciliation_result.candidate_shared_tree.rows[i].is_directory) {
                        removed_file = reconciliation_result.candidate_shared_tree.rows[i].path;
                        break;
                    }
                }
                if (removed_file.empty()) {
                    removed_file = reconciliation_result.candidate_shared_tree.rows[count].path;
                }
                detail_message += " (arquivo ausente do disco durante sync: " + removed_file + ")";
            } else {
                for (std::size_t index = 0; index < count; ++index) {
                    if (publication_tree->rows[index] !=
                        reconciliation_result.candidate_shared_tree.rows[index]) {
                        mismatch_index = index;
                        break;
                    }
                }
            }
        }
        if (mismatch_index < count) {
            const auto& actual = publication_tree->rows[mismatch_index];
            const auto& expected =
                reconciliation_result.candidate_shared_tree.rows[mismatch_index];
            detail_message += " (path=" + (expected.path.empty() ? actual.path : expected.path);
            if (actual.path != expected.path) {
                detail_message += ", actual_path=" + actual.path;
            }
            if (actual.mtime != expected.mtime) {
                detail_message += ", actual_mtime=" +
                                  std::to_string(actual.mtime.time_since_epoch().count()) +
                                  ", expected_mtime=" +
                                  std::to_string(expected.mtime.time_since_epoch().count());
            }
            if (actual.size != expected.size) {
                detail_message += ", actual_size=" + std::to_string(actual.size) +
                                  ", expected_size=" + std::to_string(expected.size);
            }
            if (actual.is_directory != expected.is_directory) {
                detail_message += ", actual_type=" + std::to_string(actual.is_directory) +
                                  ", expected_type=" + std::to_string(expected.is_directory);
            }
            detail_message += ")";
        }
        return std::unexpected(
            detail::make_error(ErrorCode::CompositionMismatch, detail_message));
    }

    if (!record->publication_required) {
        const auto found =
            std::ranges::find(observed_input.storage.reachable_commits,
                              record->observed_head_id,
                              &history::LoadedCommit::id);
        if (found == observed_input.storage.reachable_commits.end() ||
            found->commit.height != observed_input.storage.generation ||
            !same_rows(found->commit.tree.rows,
                       observed_input.storage.tree.rows) ||
            !same_rows(found->commit.tree.rows, publication_tree->rows)) {
            auto rolled = rollback_terminal();
            if (!rolled)
                return std::unexpected(rolled.error());
            std::string detail_message =
                "local materialization diverges from observed head";
            if (found != observed_input.storage.reachable_commits.end()) {
                const auto count = std::min(found->commit.tree.rows.size(),
                                            publication_tree->rows.size());
                for (std::size_t index = 0; index < count; ++index) {
                    const auto& expected = found->commit.tree.rows[index];
                    const auto& actual = publication_tree->rows[index];
                    if (actual.path != expected.path ||
                        actual.hash != expected.hash ||
                        actual.size != expected.size ||
                        actual.mtime != expected.mtime ||
                        actual.is_directory != expected.is_directory) {
                        detail_message +=
                            " (path=" + expected.path + ", actual_mtime=" +
                            std::to_string(
                                actual.mtime.time_since_epoch().count()) +
                            ", expected_mtime=" +
                            std::to_string(
                                expected.mtime.time_since_epoch().count()) +
                            ", actual_type=" +
                            std::to_string(actual.is_directory) +
                            ", expected_type=" +
                            std::to_string(expected.is_directory) + ")";
                        break;
                    }
                }
            }
            return std::unexpected(detail::make_error(
                ErrorCode::CompositionMismatch, detail_message));
        }
        std::string ff_ciphertext_id = record->ciphertext_id;
        if (ff_ciphertext_id.empty()) {
            auto it = std::ranges::find(observed_input.storage.marked_heads,
                                        found->id);
            if (it != observed_input.storage.marked_heads.end()) {
                for (const auto& identifier :
                     observed_input.storage.marked_head_identifiers) {
                    const auto parsed =
                        history_storage::parse_marker_object(identifier);
                    if (parsed && parsed->commit_id == found->id) {
                        ff_ciphertext_id = parsed->ciphertext_id;
                        break;
                    }
                }
            }
        }
        if (!state_storage::initialize(runtime_data.database_path) ||
            !state_storage::save_state(
                runtime_data.database_path,
                state_storage::StoredState{
                    .tree = found->commit.tree,
                    .height = found->commit.height,
                    .commit_id = found->id,
                    .ciphertext_id = ff_ciphertext_id,
                    .epoch_id = observed_input.storage.epoch_id,
                    .epoch_sequence = observed_input.storage.epoch_sequence})) {
            const auto database_error = detail::make_error(
                ErrorCode::DatabaseFailure, "não foi possível salvar state.db");
            auto rolled = rollback_terminal();
            if (!rolled) {
                return std::unexpected(detail::make_error(
                    ErrorCode::RecoveryConflict,
                    database_error.detail +
                        "; rollback falhou: " + rolled.error().detail));
            }
            return std::unexpected(database_error);
        }
        record->phase = transaction::Phase::DatabaseCommitted;
        saved = detail::save_record(*paths, *record, key);
        if (!saved)
            return std::unexpected(saved.error());
        record->phase = transaction::Phase::CleanupCompleted;
        saved = detail::save_record(*paths, *record, key);
        if (!saved)
            return std::unexpected(saved.error());
        return detail::finish_transaction_cleanup(*paths,
                                                  transaction_workspace);
    }

    if (!prepared_commit || !commit_publication.valid()) {
        auto rolled = rollback_terminal();
        if (!rolled)
            return std::unexpected(rolled.error());
        return std::unexpected(detail::make_error(
            ErrorCode::PublicationFailure,
            "speculative commit publication was not initialized"));
    }
    record->commit_id = prepared_commit->commit_id;
    record->parent_ids = prepared_commit->commit.parents;
    record->phase = transaction::Phase::CommitPrepared;
    saved = detail::save_record(*paths, *record, key);
    if (!saved)
        return std::unexpected(saved.error());

    publication::PublishObjectResult published;
    try {
        published = commit_publication.get();
    } catch (const std::exception& exception) {
        auto rolled = rollback_terminal();
        if (!rolled)
            return std::unexpected(rolled.error());
        return std::unexpected(
            detail::make_error(ErrorCode::PublicationFailure,
                               std::string{"commit publication task failed: "} +
                                   exception.what()));
    }
    if (!published) {
        auto rolled = rollback_terminal();
        if (!rolled)
            return std::unexpected(rolled.error());
        return std::unexpected(publication_error(published.error()));
    }
    record->ciphertext_id = published->head.ciphertext_id;
    record->marker_id = published->marker_id;
    record->phase = transaction::Phase::CommitUploaded;
    saved = detail::save_record(*paths, *record, key);
    if (!saved)
        return std::unexpected(saved.error());
    record->phase = transaction::Phase::CommitVerified;
    saved = detail::save_record(*paths, *record, key);
    if (!saved)
        return std::unexpected(saved.error());

    const auto head_put_trace = platform::perf_trace::begin();
    auto marker_published = publication::publish_head_marker(
        storage, published->head, runtime_data.database_path.parent_path());
    platform::perf_trace::finish("head PUT", head_put_trace);
    if (!marker_published) {
        auto inspected = publication::inspect_head_marker(
            storage, published->head, runtime_data.database_path.parent_path());
        if (!inspected) {
            return std::unexpected(detail::indeterminate_publication(
                inspected.error(), "head marker publication"));
        }
        if (*inspected != publication::HeadMarkerState::Valid) {
            auto rolled = rollback_terminal();
            if (!rolled)
                return std::unexpected(rolled.error());
            return std::unexpected(publication_error(marker_published.error()));
        }
    }
    record->phase = transaction::Phase::HeadPublished;
    saved = detail::save_record(*paths, *record, key);
    if (!saved)
        return std::unexpected(saved.error());

    const auto head_verification_trace = platform::perf_trace::begin();
    auto head_verified = publication::verify_head_marker(
        storage,
        published->head,
        runtime_data.database_path.parent_path(),
        marker_published ? marker_published->physical_hash
                         : std::string_view{});
    platform::perf_trace::finish("head verification", head_verification_trace);
    if (!head_verified) {
        if (head_verified.error().code ==
            publication::ErrorCode::VerificationFailure) {
            auto rolled = rollback_terminal();
            if (!rolled)
                return std::unexpected(rolled.error());
            return std::unexpected(publication_error(head_verified.error()));
        }
        auto inspected = publication::inspect_head_marker(
            storage, published->head, runtime_data.database_path.parent_path());
        if (!inspected) {
            return std::unexpected(detail::indeterminate_publication(
                inspected.error(), "head marker verification"));
        }
        if (*inspected != publication::HeadMarkerState::Valid) {
            auto rolled = rollback_terminal();
            if (!rolled)
                return std::unexpected(rolled.error());
            return std::unexpected(publication_error(head_verified.error()));
        }
    }
    record->phase = transaction::Phase::HeadVerified;
    saved = detail::save_record(*paths, *record, key);
    if (!saved)
        return std::unexpected(saved.error());

    std::optional<history_storage::epoch::Reference> verified_new_epoch;
    if (prepared_commit->commit.parents.empty()) {
        history_storage::epoch::RetentionPolicy policy{
            .min_history_depth = runtime_data.min_history_depth,
            .min_history_age_hours = runtime_data.min_history_age_hours};
        auto epoch = detail::prepare_genesis_epoch(*record, policy, key);
        if (!epoch) {
            return std::unexpected(epoch.error());
        }
        record->phase = transaction::Phase::EpochPrepared;
        saved = detail::save_record(*paths, *record, key);
        if (!saved)
            return std::unexpected(saved.error());

        auto epoch_published = history_storage::epoch::publish(
            storage, *epoch, runtime_data.database_path.parent_path());
        if (!epoch_published) {
            auto visible = history_storage::epoch::verify(
                storage,
                detail::genesis_epoch(*record),
                epoch->reference,
                key,
                runtime_data.database_path.parent_path());
            if (!visible) {
                return std::unexpected(
                    detail::make_error(ErrorCode::PublicationFailure,
                                       "não foi possível publicar o Epoch gênesis: " +
                                           epoch_published.error().detail));
            }
        }
        record->phase = transaction::Phase::EpochUploaded;
        saved = detail::save_record(*paths, *record, key);
        if (!saved)
            return std::unexpected(saved.error());

        auto epoch_verified = history_storage::epoch::verify(
            storage,
            detail::genesis_epoch(*record),
            epoch->reference,
            key,
            runtime_data.database_path.parent_path());
        if (!epoch_verified) {
            return std::unexpected(
                detail::make_error(ErrorCode::PublicationFailure,
                                   "não foi possível verificar o Epoch gênesis: " +
                                       epoch_verified.error().detail));
        }
        record->phase = transaction::Phase::EpochVerified;
        saved = detail::save_record(*paths, *record, key);
        if (!saved)
            return std::unexpected(saved.error());
        verified_new_epoch = epoch->reference;
    } else if (!observed_input.storage.epoch_id.empty()) {
        auto policy =
            detail::authenticated_epoch_policy(observed_input.storage);
        if (!policy) {
            return std::unexpected(policy.error());
        }

        std::vector<history::LoadedCommit> current_dag =
            observed_input.storage.reachable_commits;
        current_dag.push_back(
            history::LoadedCommit{.id = prepared_commit->commit_id,
                                  .commit = prepared_commit->commit});

        if (commit_time->pruning_time_safe) {
            auto plan =
                history_storage::epoch::plan_pruning(current_dag, *policy);
            if (plan &&
                !detail::same_epoch_frontier(
                    observed_input.storage.epoch_anchors, plan->anchors)) {
                auto epoch = detail::prepare_pruning_epoch(
                    *record,
                    *policy,
                    *plan,
                    observed_input.storage.epoch_vault_id,
                    observed_input.storage.epoch_sequence,
                    observed_input.storage.epoch_id,
                    key);
                if (!epoch) {
                    return std::unexpected(epoch.error());
                }

                const history_storage::epoch::Epoch expected_epoch{
                    .vault_id = observed_input.storage.epoch_vault_id,
                    .sequence = epoch->reference.sequence,
                    .issued_at = record->epoch_issued_at,
                    .policy = *policy,
                    .anchors = plan->anchors,
                    .previous_epoch_id = observed_input.storage.epoch_id};

                auto epoch_published = history_storage::epoch::publish(
                    storage, *epoch, runtime_data.database_path.parent_path());
                if (!epoch_published) {
                    auto visible = history_storage::epoch::verify(
                        storage,
                        expected_epoch,
                        epoch->reference,
                        key,
                        runtime_data.database_path.parent_path());
                    if (!visible) {
                        return std::unexpected(detail::make_error(
                            ErrorCode::PublicationFailure,
                            "não foi possível publicar o Epoch de poda: " +
                                epoch_published.error().detail));
                    }
                }

                record->phase = transaction::Phase::EpochUploaded;
                saved = detail::save_record(*paths, *record, key);
                if (!saved) {
                    return std::unexpected(saved.error());
                }

                auto epoch_verified = history_storage::epoch::verify(
                    storage,
                    expected_epoch,
                    epoch->reference,
                    key,
                    runtime_data.database_path.parent_path());
                if (!epoch_verified) {
                    return std::unexpected(
                        detail::make_error(ErrorCode::PublicationFailure,
                                           "não foi possível verificar o Epoch de poda: " +
                                               epoch_verified.error().detail));
                }

                record->phase = transaction::Phase::EpochVerified;
                saved = detail::save_record(*paths, *record, key);
                if (!saved) {
                    return std::unexpected(saved.error());
                }
                verified_new_epoch = epoch->reference;
            }
        }
    }

    auto epoch_reference = detail::epoch_reference_for_state(
        observed_input.storage, verified_new_epoch);
    if (!epoch_reference) {
        return std::unexpected(epoch_reference.error());
    }
    const auto database_trace = platform::perf_trace::begin();
    const bool database_saved =
        state_storage::initialize(runtime_data.database_path) &&
        state_storage::save_state(
            runtime_data.database_path,
            state_storage::StoredState{
                .tree = prepared_commit->commit.tree,
                .height = prepared_commit->commit.height,
                .commit_id = prepared_commit->commit_id,
                .ciphertext_id = published->head.ciphertext_id,
                .epoch_id = *epoch_reference ? (**epoch_reference).epoch_id
                                             : std::string{},
                .epoch_sequence =
                    *epoch_reference ? (**epoch_reference).sequence : 0});
    platform::perf_trace::finish("local DB commit", database_trace);
    if (!database_saved) {
        return std::unexpected(detail::make_error(ErrorCode::DatabaseFailure,
                                                  "não foi possível salvar state.db"));
    }
    record->phase = transaction::Phase::DatabaseCommitted;
    saved = detail::save_record(*paths, *record, key);
    if (!saved)
        return std::unexpected(saved.error());

    auto observed_cleanup_ids = prepared_commit->commit.parents;
    observed_cleanup_ids.insert(
        observed_cleanup_ids.end(),
        observed_input.storage.ancestral_marked_heads.begin(),
        observed_input.storage.ancestral_marked_heads.end());
    const auto cleanup_trace = platform::perf_trace::begin();
    auto post_prune = publication::prune_observed_parent_markers(
        storage,
        observed_cleanup_ids,
        observed_input.storage.marked_head_identifiers);
    platform::perf_trace::finish("marker cleanup", cleanup_trace);
    if (!post_prune) {
        return std::unexpected(detail::indeterminate_publication(
            post_prune.error(), "marker pruning"));
    }
    record->phase = transaction::Phase::CleanupCompleted;
    saved = detail::save_record(*paths, *record, key);
    if (!saved)
        return std::unexpected(saved.error());
    return detail::finish_transaction_cleanup(*paths, transaction_workspace);
}

} // namespace kasumi::application::sync::coordinator
