#include "core/transaction/codec.hpp"

#include "core/history.hpp"
#include "core/wire.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <utility>

namespace kasumi::transaction::codec {

namespace {

inline constexpr std::uint8_t format_version = 9;
inline constexpr std::size_t maximum_string_size = 4096;
inline constexpr std::uint32_t maximum_operation_count = 1'000'000;

bool valid_string(std::string_view value) noexcept {
    return value.size() <= maximum_string_size;
}

bool valid_operation_strings(const kasumi::Operation& operation,
                             const OperationProgress& progress) {
    return valid_string(platform::path::to_logical_utf8(operation.path)) &&
           valid_string(platform::path::to_logical_utf8(operation.alt_path)) &&
           valid_string(operation.hash) && valid_string(progress.previous_hash);
}

} // namespace

EncodeResult encode(const Record& record) {
    if (!valid(record)) {
        return std::unexpected("registro transacional inválido");
    }
    try {
        if (sync_plan_size(record.plan) > maximum_operation_count ||
            !valid_string(record.operation_id) ||
            !valid_string(record.observed_head_id) ||
            !valid_string(record.commit_id) ||
            !valid_string(record.ciphertext_id) ||
            !valid_string(record.marker_id) ||
            !valid_string(record.epoch_vault_id) ||
            !valid_string(record.epoch_id) ||
            record.parent_ids.size() > history::maximum_parent_count) {
            return std::unexpected(
                "registro transacional excede os limites do codec");
        }
        for (std::size_t index = 0; index < sync_plan_size(record.plan);
             ++index) {
            if (!valid_operation_strings(record.plan.operations[index],
                                         record.progress[index])) {
                return std::unexpected(
                    "string de operação excede o limite do codec");
            }
        }

        wire::Writer writer;
        wire::write<std::uint8_t>(writer, format_version);
        wire::write_string(writer, record.operation_id);
        wire::write<std::uint8_t>(writer,
                                  static_cast<std::uint8_t>(record.phase));
        wire::write<std::uint8_t>(writer, record.publication_required ? 1 : 0);
        wire::write_string(writer, record.observed_head_id);
        wire::write<std::uint64_t>(writer, record.local_generation);
        wire::write<std::uint64_t>(writer, record.storage_generation);
        wire::write<std::uint64_t>(writer, record.plan.target_generation);
        wire::write_string(writer, record.commit_id);
        wire::write_string(writer, record.ciphertext_id);
        wire::write_string(writer, record.marker_id);
        wire::write_string(writer, record.epoch_vault_id);
        wire::write_string(writer, record.epoch_id);
        wire::write<std::int64_t>(writer, record.epoch_issued_at);
        wire::write<std::uint32_t>(writer, record.epoch_min_history_depth);
        wire::write<std::uint32_t>(writer, record.epoch_min_history_age_hours);
        wire::write<std::uint32_t>(
            writer, static_cast<std::uint32_t>(record.parent_ids.size()));
        for (const auto& parent_id : record.parent_ids) {
            if (!valid_string(parent_id)) {
                return std::unexpected("parent ID excede o limite do codec");
            }
            wire::write_string(writer, parent_id);
        }

        wire::write<std::uint32_t>(
            writer, static_cast<std::uint32_t>(sync_plan_size(record.plan)));
        for (std::size_t index = 0; index < sync_plan_size(record.plan);
             ++index) {
            const auto& operation = record.plan.operations[index];
            const auto& progress = record.progress[index];

            wire::write<std::uint8_t>(
                writer, static_cast<std::uint8_t>(operation.action));
            wire::write_string(writer,
                               platform::path::to_logical_utf8(operation.path));
            wire::write_string(
                writer, platform::path::to_logical_utf8(operation.alt_path));
            wire::write_string(writer, operation.hash);
            wire::write<std::uint64_t>(writer, operation.size);
            wire::write<std::uint8_t>(writer,
                                      operation.exclusive_destination ? 1 : 0);

            wire::write_string(writer, progress.previous_hash);
            wire::write<std::uint32_t>(writer, progress.backup_slot);
            wire::write<std::uint8_t>(
                writer, static_cast<std::uint8_t>(progress.state));
            wire::write<std::uint8_t>(writer, progress.had_original ? 1 : 0);
        }
        return std::move(writer.buffer);
    } catch (const std::exception& exception) {
        return std::unexpected(
            std::string{"falha ao codificar registro transacional: "} +
            exception.what());
    }
}

std::expected<Record, std::string> decode(std::span<const std::byte> data) {
    try {
        wire::Reader reader{data};

        auto version = wire::read<std::uint8_t>(reader);
        if (!version || *version != format_version) {
            return std::unexpected("versão inválida ou legado (removido)");
        }

        auto id = wire::read_string(reader, maximum_string_size);
        auto phase_raw = wire::read<std::uint8_t>(reader);
        auto publication_required = wire::read<std::uint8_t>(reader);
        auto observed_head_id = wire::read_string(reader, maximum_string_size);
        auto local = wire::read<std::uint64_t>(reader);
        auto storage = wire::read<std::uint64_t>(reader);
        auto target = wire::read<std::uint64_t>(reader);
        auto commit_id = wire::read_string(reader, maximum_string_size);
        auto ciphertext_id = wire::read_string(reader, maximum_string_size);
        auto marker_id = wire::read_string(reader, maximum_string_size);
        auto epoch_vault_id = wire::read_string(reader, maximum_string_size);
        auto epoch_id = wire::read_string(reader, maximum_string_size);
        auto epoch_issued_at = wire::read<std::int64_t>(reader);
        auto epoch_min_history_depth = wire::read<std::uint32_t>(reader);
        auto epoch_min_history_age_hours = wire::read<std::uint32_t>(reader);
        auto parent_count = wire::read<std::uint32_t>(reader);
        if (!id || !phase_raw || !publication_required || !observed_head_id ||
            !local || !storage || !target || !commit_id || !ciphertext_id ||
            !marker_id || !epoch_vault_id || !epoch_id || !epoch_issued_at ||
            !epoch_min_history_depth || !epoch_min_history_age_hours ||
            !parent_count) {
            return std::unexpected("campos ausentes");
        }
        if (*publication_required > 1) {
            return std::unexpected("booleano de publicação inválido");
        }

        const auto phase = static_cast<Phase>(*phase_raw);
        if (!valid(phase)) {
            return std::unexpected("fase desconhecida");
        }

        Record record;
        record.operation_id = std::move(*id);
        record.phase = phase;
        record.publication_required = *publication_required == 1;
        record.observed_head_id = std::move(*observed_head_id);
        record.local_generation = *local;
        record.storage_generation = *storage;
        record.plan.target_generation = *target;
        record.commit_id = std::move(*commit_id);
        record.ciphertext_id = std::move(*ciphertext_id);
        record.marker_id = std::move(*marker_id);
        record.epoch_vault_id = std::move(*epoch_vault_id);
        record.epoch_id = std::move(*epoch_id);
        record.epoch_issued_at = *epoch_issued_at;
        record.epoch_min_history_depth = *epoch_min_history_depth;
        record.epoch_min_history_age_hours = *epoch_min_history_age_hours;
        if (*parent_count > history::maximum_parent_count) {
            return std::unexpected("tamanho de parents excede o limite");
        }
        record.parent_ids.reserve(*parent_count);
        for (std::uint32_t index = 0; index < *parent_count; ++index) {
            auto parent_id = wire::read_string(reader, maximum_string_size);
            if (!parent_id) {
                return std::unexpected("parent ID ausente");
            }
            record.parent_ids.push_back(std::move(*parent_id));
        }

        auto count = wire::read<std::uint32_t>(reader);
        if (!count) {
            return std::unexpected("truncado no ops count");
        }
        if (*count > maximum_operation_count) {
            return std::unexpected("tamanho de ops excede o limite");
        }

        record.plan.operations.reserve(*count);
        record.progress.reserve(*count);
        for (std::uint32_t index = 0; index < *count; ++index) {
            auto action_raw = wire::read<std::uint8_t>(reader);
            auto path = wire::read_string(reader, maximum_string_size);
            auto alt_path = wire::read_string(reader, maximum_string_size);
            auto hash = wire::read_string(reader, maximum_string_size);
            auto size = wire::read<std::uint64_t>(reader);
            auto exclusive = wire::read<std::uint8_t>(reader);
            auto previous_hash = wire::read_string(reader, maximum_string_size);
            auto backup = wire::read<std::uint32_t>(reader);
            auto state_raw = wire::read<std::uint8_t>(reader);
            auto had_original = wire::read<std::uint8_t>(reader);

            if (!action_raw || !path || !alt_path || !hash || !size ||
                !exclusive || !previous_hash || !backup || !state_raw ||
                !had_original) {
                return std::unexpected("operação truncada");
            }
            if (!is_valid_action(static_cast<kasumi::Action>(*action_raw))) {
                return std::unexpected("ação inválida");
            }
            if (*exclusive > 1 || *had_original > 1) {
                return std::unexpected("booleano inválido");
            }

            const auto state = static_cast<OperationState>(*state_raw);
            if (!valid(state)) {
                return std::unexpected("estado inválido");
            }

            record.plan.operations.push_back(kasumi::Operation{
                .action = static_cast<kasumi::Action>(*action_raw),
                .path = platform::path::from_utf8(*path),
                .hash = std::move(*hash),
                .alt_path = platform::path::from_utf8(*alt_path),
                .size = *size,
                .exclusive_destination = *exclusive == 1,
            });
            record.progress.push_back(OperationProgress{
                .previous_hash = std::move(*previous_hash),
                .backup_slot = *backup,
                .state = state,
                .had_original = *had_original == 1,
            });
        }

        if (!std::ranges::is_sorted(record.plan.operations,
                                    {},
                                    [](const kasumi::Operation& operation) {
                                        return action_index(operation.action);
                                    })) {
            return std::unexpected("ordem canônica inválida");
        }

        rebuild_sync_plan_offsets(record.plan);
        if (!reader.data.empty()) {
            return std::unexpected("bytes residuais após o registro");
        }
        if (!valid(record)) {
            return std::unexpected("registro inválido");
        }
        return record;
    } catch (const std::exception& exception) {
        return std::unexpected(
            std::string{"falha ao decodificar registro transacional: "} +
            exception.what());
    }
}

} // namespace kasumi::transaction::codec
