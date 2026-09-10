#include "core/transaction/types.hpp"

#include "core/history.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <utility>

namespace kasumi::transaction {

namespace {

bool valid_local_only_phase(Phase phase) noexcept {
    switch (phase) {
        case Phase::Started:
        case Phase::FilesStaged:
        case Phase::LocalChangesApplied:
        case Phase::DatabaseCommitted:
        case Phase::CleanupCompleted:
            return true;
        case Phase::CommitPrepared:
        case Phase::CommitUploaded:
        case Phase::CommitVerified:
        case Phase::HeadPublished:
        case Phase::HeadVerified:
        case Phase::EpochPrepared:
        case Phase::EpochUploaded:
        case Phase::EpochVerified:
            return false;
    }
    return false;
}

bool valid_publication_phase(Phase phase) noexcept {
    return valid(phase);
}

} // namespace

bool valid(Phase phase) noexcept {
    return phase >= Phase::Started && phase <= Phase::CleanupCompleted;
}

bool valid(OperationState state) noexcept {
    return state >= OperationState::Pending && state <= OperationState::Applied;
}

bool valid_transaction_id(std::string_view value) noexcept {
    if (value.size() != transaction_id_hex_size) {
        return false;
    }
    for (const char character : value) {
        const bool digit = character >= '0' && character <= '9';
        const bool letter = character >= 'a' && character <= 'f';
        if (!digit && !letter) {
            return false;
        }
    }
    return true;
}

bool valid(const Record& record) noexcept {
    const bool commit_required =
        record.publication_required && record.phase >= Phase::CommitPrepared;
    const bool object_required =
        record.publication_required && record.phase >= Phase::CommitUploaded;
    const bool genesis = commit_required &&
                         record.plan.target_generation == 0 &&
                         record.parent_ids.empty();
    const bool pruning_epoch = !genesis && !record.epoch_vault_id.empty();
    const bool epoch_phase = record.phase >= Phase::EpochPrepared &&
                             record.phase <= Phase::EpochVerified;
    const bool epoch_required =
        (genesis || pruning_epoch) && record.phase >= Phase::EpochPrepared;
    if (!valid_transaction_id(record.operation_id) ||
        !valid_publication_phase(record.phase) ||
        !valid_sync_plan(record.plan) ||
        record.local_generation > record.storage_generation ||
        record.storage_generation ==
            std::numeric_limits<std::uint64_t>::max() ||
        (record.publication_required && !record.observed_head_id.empty()) ||
        (!record.publication_required &&
         (!kasumi::history::valid_commit_id(record.observed_head_id) ||
          !valid_local_only_phase(record.phase))) ||
        (!commit_required &&
         (!record.commit_id.empty() || !record.ciphertext_id.empty() ||
          !record.marker_id.empty() || !record.parent_ids.empty())) ||
        (commit_required &&
         !kasumi::history::valid_commit_id(record.commit_id)) ||
        (object_required &&
         (!kasumi::history::valid_commit_id(record.ciphertext_id) ||
          record.marker_id.empty())) ||
        (!object_required &&
         (!record.ciphertext_id.empty() || !record.marker_id.empty())) ||
        (epoch_phase && !genesis && !pruning_epoch) ||
        (epoch_required &&
         (!kasumi::history::valid_commit_id(record.epoch_vault_id) ||
          !kasumi::history::valid_commit_id(record.epoch_id) ||
          record.epoch_issued_at < 0 || record.epoch_min_history_depth == 0 ||
          record.epoch_min_history_depth > history::maximum_graph_depth ||
          record.epoch_min_history_age_hours == 0)) ||
        (!epoch_required &&
         (!record.epoch_vault_id.empty() || !record.epoch_id.empty() ||
          record.epoch_issued_at != 0 || record.epoch_min_history_depth != 0 ||
          record.epoch_min_history_age_hours != 0)) ||
        (record.publication_required &&
         ((record.storage_generation != 0 ||
           record.plan.target_generation != 0) &&
          record.plan.target_generation != record.storage_generation + 1)) ||
        (!record.publication_required &&
         record.plan.target_generation != record.storage_generation) ||
        record.progress.size() != sync_plan_size(record.plan)) {
        return false;
    }
    if (commit_required) {
        if (record.parent_ids.size() > history::maximum_parent_count ||
            !std::ranges::is_sorted(record.parent_ids) ||
            std::ranges::adjacent_find(record.parent_ids) !=
                record.parent_ids.end() ||
            std::ranges::any_of(record.parent_ids, [](std::string_view id) {
                return !history::valid_commit_id(id);
            })) {
            return false;
        }
    }
    for (const auto& operation : record.plan.operations) {
        if (!has_safe_paths(operation)) {
            return false;
        }
    }

    std::uint32_t next_backup = 0;
    const auto no_backup = std::numeric_limits<std::uint32_t>::max();
    for (std::size_t index = 0; index < sync_plan_size(record.plan); ++index) {
        if (!valid(record.progress[index].state))
            return false;
        const auto expected =
            is_local_mutation(record.plan.operations[index].action)
                ? next_backup++
                : no_backup;
        if (record.progress[index].backup_slot != expected)
            return false;
    }
    return true;
}

std::expected<Record, std::string> make_record(std::string transaction_id,
                                               std::uint64_t local_generation,
                                               std::uint64_t storage_generation,
                                               SyncPlan plan,
                                               bool publication_required,
                                               std::string observed_head_id) {
    if (!valid_transaction_id(transaction_id)) {
        return std::unexpected("identificador transacional inválido");
    }
    if (!valid_sync_plan(plan)) {
        return std::unexpected("plano transacional inválido");
    }
    for (const auto& operation : plan.operations) {
        if (!has_safe_paths(operation)) {
            return std::unexpected(
                "plano transacional contém caminho inseguro");
        }
    }
    if (local_generation > storage_generation) {
        return std::unexpected(
            "geração local superior à geração do armazenamento");
    }
    if (storage_generation == std::numeric_limits<std::uint64_t>::max()) {
        return std::unexpected(
            "geração do armazenamento não pode atingir o máximo");
    }
    if (publication_required &&
        (storage_generation != 0 || plan.target_generation != 0) &&
        plan.target_generation != storage_generation + 1) {
        return std::unexpected("geração alvo incompatível com o armazenamento");
    }
    if (!publication_required && plan.target_generation != storage_generation) {
        return std::unexpected("geração local não pode publicar estado");
    }
    if (!publication_required && !history::valid_commit_id(observed_head_id)) {
        return std::unexpected("logical head observada inválida");
    }

    Record record{
        .operation_id = std::move(transaction_id),
        .phase = Phase::Started,
        .publication_required = publication_required,
        .observed_head_id = std::move(observed_head_id),
        .local_generation = local_generation,
        .storage_generation = storage_generation,
        .commit_id = {},
        .ciphertext_id = {},
        .parent_ids = {},
        .marker_id = {},
        .epoch_vault_id = {},
        .epoch_id = {},
        .epoch_issued_at = 0,
        .epoch_min_history_depth = 0,
        .epoch_min_history_age_hours = 0,
        .plan = std::move(plan),
        .progress = {},
    };
    record.progress.resize(sync_plan_size(record.plan));

    std::uint32_t backup_slot = 0;
    const auto no_backup = std::numeric_limits<std::uint32_t>::max();
    for (std::size_t index = 0; index < sync_plan_size(record.plan); ++index) {
        record.progress[index].backup_slot =
            is_local_mutation(record.plan.operations[index].action)
                ? backup_slot++
                : no_backup;
    }

    if (!valid(record)) {
        return std::unexpected("registro transacional inválido");
    }
    return record;
}

} // namespace kasumi::transaction
