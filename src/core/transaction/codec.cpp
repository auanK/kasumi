#include "core/transaction/codec.hpp"

#include "core/history.hpp"
#include "core/wire.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <utility>

namespace kasumi::transaction::codec {

namespace {

inline constexpr std::uint8_t format_version = 10;
inline constexpr std::uint8_t oldest_supported_format_version = 9;
inline constexpr std::size_t maximum_string_size = 4096;
inline constexpr std::uint32_t maximum_operation_count = 1'000'000;
inline constexpr std::uint32_t maximum_pending_path_count = 1'000'000;

bool valid_string(std::string_view value) noexcept {
    return value.size() <= maximum_string_size;
}

bool valid_operation_strings(const kasumi::Operation& operation,
                             const OperationProgress& progress) {
    return valid_string(platform::path::to_logical_utf8(operation.path)) &&
           valid_string(platform::path::to_logical_utf8(operation.alt_path)) &&
           valid_string(operation.hash) && valid_string(progress.previous_hash);
}

inline constexpr std::array persisted_actions{
    kasumi::Action::RenameLocal,
    kasumi::Action::Upload,
    kasumi::Action::CreateLocalDirectory,
    kasumi::Action::CreateRemoteDirectory,
    kasumi::Action::Download,
    kasumi::Action::DeleteLocal,
    kasumi::Action::DeleteLocalDirectory,
    kasumi::Action::DeleteRemote,
    kasumi::Action::DeleteRemoteDirectory,
    kasumi::Action::MoveLocal,
    kasumi::Action::CopyLocal,
    kasumi::Action::DeleteIgnoredLocalFile,
};

constexpr std::optional<std::uint8_t>
persisted_action_id(kasumi::Action action) noexcept {
    const auto it = std::ranges::find(persisted_actions, action);
    if (it == persisted_actions.end()) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>(it - persisted_actions.begin());
}

constexpr std::optional<kasumi::Action>
action_from_persisted_id(std::uint8_t id) noexcept {
    return id < persisted_actions.size()
               ? std::optional<kasumi::Action>{persisted_actions[id]}
               : std::nullopt;
}

void write_strings(wire::Writer& writer, std::span<const std::string> values) {
    wire::write<std::uint32_t>(writer,
                               static_cast<std::uint32_t>(values.size()));
    for (const auto& value : values) {
        wire::write_string(writer, value);
    }
}

bool read_strings(wire::Reader& reader,
                  std::vector<std::string>& out,
                  std::size_t max_count,
                  bool* overflow = nullptr) {
    auto count = wire::read<std::uint32_t>(reader);
    if (!count) {
        return false;
    }
    if (*count > max_count ||
        *count > reader.data.size() / sizeof(std::uint32_t)) {
        if (overflow != nullptr) {
            *overflow = true;
        }
        return false;
    }
    out.reserve(*count);
    for (std::uint32_t index = 0; index < *count; ++index) {
        auto item = wire::read_string(reader, maximum_string_size);
        if (!item) {
            return false;
        }
        out.push_back(std::move(*item));
    }
    return true;
}

} // namespace

std::expected<void, std::string> validate(const Record& record) {
    if (!valid(record)) {
        return std::unexpected("invalid transaction record");
    }
    try {
        if (sync_plan_size(record.plan) > maximum_operation_count ||
            !valid_string(record.marker_id) ||
            record.parent_ids.size() > history::maximum_parent_count ||
            record.observed_pending_paths.size() > maximum_pending_path_count ||
            record.pending_paths.size() > maximum_pending_path_count) {
            return std::unexpected("transaction record exceeds codec limits");
        }
        for (std::size_t index = 0; index < sync_plan_size(record.plan);
             ++index) {
            if (!valid_operation_strings(record.plan.operations[index],
                                         record.progress[index])) {
                return std::unexpected("operation string exceeds codec limit");
            }
        }
        const auto too_long = [](std::string_view value) {
            return !valid_string(value);
        };
        if (std::ranges::any_of(record.observed_pending_paths, too_long) ||
            std::ranges::any_of(record.pending_paths, too_long)) {
            return std::unexpected("transaction string exceeds codec limit");
        }
        return {};
    } catch (const std::exception& error) {
        return std::unexpected(
            std::string{"failed to validate transaction record: "} +
            error.what());
    }
}

EncodeResult encode(const Record& record) {
    auto validation = validate(record);
    if (!validation)
        return std::unexpected(validation.error());
    try {
        wire::Writer writer;
        wire::write<std::uint8_t>(writer, format_version);
        wire::write_string(writer, record.operation_id);
        wire::write<std::uint8_t>(writer,
                                  static_cast<std::uint8_t>(record.phase));
        wire::write<std::uint8_t>(writer, record.publication_required ? 1 : 0);
        wire::write_string(writer, record.observed_head_id);
        wire::write_string(writer, record.observed_base_id);
        wire::write<std::uint64_t>(writer, record.local_generation);
        wire::write<std::uint64_t>(writer, record.storage_generation);
        write_strings(writer, record.observed_pending_paths);
        write_strings(writer, record.pending_paths);
        wire::write<std::uint64_t>(writer, record.plan.target_generation);
        wire::write_string(writer, record.commit_id);
        wire::write_string(writer, record.ciphertext_id);
        wire::write_string(writer, record.marker_id);
        wire::write_string(writer, record.epoch_vault_id);
        wire::write_string(writer, record.epoch_id);
        wire::write<std::int64_t>(writer, record.epoch_issued_at);
        wire::write<std::uint32_t>(writer, record.epoch_min_history_depth);
        wire::write<std::uint32_t>(writer, record.epoch_min_history_age_hours);
        write_strings(writer, record.parent_ids);

        wire::write<std::uint32_t>(
            writer, static_cast<std::uint32_t>(sync_plan_size(record.plan)));
        for (std::size_t index = 0; index < sync_plan_size(record.plan);
             ++index) {
            const auto& operation = record.plan.operations[index];
            const auto& progress = record.progress[index];

            const auto action_id = persisted_action_id(operation.action);
            if (!action_id) {
                return std::unexpected("invalid action");
            }
            wire::write<std::uint8_t>(writer, *action_id);
            wire::write_string(writer,
                               platform::path::to_logical_utf8(operation.path));
            wire::write_string(
                writer, platform::path::to_logical_utf8(operation.alt_path));
            wire::write_string(writer, operation.hash);
            wire::write<std::uint64_t>(writer, operation.size);
            wire::write<std::uint8_t>(writer,
                                      operation.exclusive_destination ? 1 : 0);
            if (operation.action == kasumi::Action::DeleteIgnoredLocalFile) {
                wire::write<std::uint64_t>(
                    writer, operation.expected_source_identity.volume_or_dev);
                wire::write<std::uint64_t>(
                    writer, operation.expected_source_identity.file_id_low);
                wire::write<std::uint64_t>(
                    writer, operation.expected_source_identity.file_id_high);
                wire::write<std::uint8_t>(
                    writer, operation.expected_source_identity.valid ? 1 : 0);
            }

            wire::write_string(writer, progress.previous_hash);
            wire::write<std::uint32_t>(writer, progress.backup_slot);
            wire::write<std::uint8_t>(
                writer, static_cast<std::uint8_t>(progress.state));
            wire::write<std::uint8_t>(writer, progress.had_original ? 1 : 0);
        }
        return std::move(writer.buffer);
    } catch (const std::exception& exception) {
        return std::unexpected(
            std::string{"failed to encode transaction record: "} +
            exception.what());
    }
}

std::expected<Record, std::string> decode(std::span<const std::byte> data) {
    try {
        wire::Reader reader{data};

        auto version = wire::read<std::uint8_t>(reader);
        if (!version || *version < oldest_supported_format_version ||
            *version > format_version) {
            return std::unexpected("unsupported journal format version");
        }

        auto id = wire::read_string(reader, maximum_string_size);
        auto phase_raw = wire::read<std::uint8_t>(reader);
        auto publication_required = wire::read<std::uint8_t>(reader);
        auto observed_head_id = wire::read_string(reader, maximum_string_size);
        auto observed_base_id = wire::read_string(reader, maximum_string_size);
        auto local = wire::read<std::uint64_t>(reader);
        auto storage = wire::read<std::uint64_t>(reader);
        std::vector<std::string> observed_pending_paths;
        std::vector<std::string> pending_paths;
        const bool pending_fields_present =
            read_strings(
                reader, observed_pending_paths, maximum_pending_path_count) &&
            read_strings(reader, pending_paths, maximum_pending_path_count);
        auto target = wire::read<std::uint64_t>(reader);
        auto commit_id = wire::read_string(reader, maximum_string_size);
        auto ciphertext_id = wire::read_string(reader, maximum_string_size);
        auto marker_id = wire::read_string(reader, maximum_string_size);
        auto epoch_vault_id = wire::read_string(reader, maximum_string_size);
        auto epoch_id = wire::read_string(reader, maximum_string_size);
        auto epoch_issued_at = wire::read<std::int64_t>(reader);
        auto epoch_min_history_depth = wire::read<std::uint32_t>(reader);
        auto epoch_min_history_age_hours = wire::read<std::uint32_t>(reader);
        if (!id || !phase_raw || !publication_required || !observed_head_id ||
            !observed_base_id || !local || !storage ||
            !pending_fields_present || !target || !commit_id ||
            !ciphertext_id || !marker_id || !epoch_vault_id || !epoch_id ||
            !epoch_issued_at || !epoch_min_history_depth ||
            !epoch_min_history_age_hours) {
            return std::unexpected("missing fields");
        }
        bool parents_overflow = false;
        std::vector<std::string> parent_ids;
        if (!read_strings(reader,
                          parent_ids,
                          history::maximum_parent_count,
                          &parents_overflow)) {
            return std::unexpected(parents_overflow
                                       ? "parent count exceeds limit"
                                       : "missing parent ID");
        }
        if (*publication_required > 1) {
            return std::unexpected("invalid publication boolean");
        }

        const auto phase = static_cast<Phase>(*phase_raw);
        if (!valid(phase)) {
            return std::unexpected("unknown phase");
        }

        Record record{
            .operation_id = std::move(*id),
            .phase = phase,
            .publication_required = *publication_required == 1,
            .observed_head_id = std::move(*observed_head_id),
            .observed_base_id = std::move(*observed_base_id),
            .local_generation = *local,
            .storage_generation = *storage,
            .observed_pending_paths = std::move(observed_pending_paths),
            .pending_paths = std::move(pending_paths),
            .commit_id = std::move(*commit_id),
            .ciphertext_id = std::move(*ciphertext_id),
            .parent_ids = std::move(parent_ids),
            .marker_id = std::move(*marker_id),
            .epoch_vault_id = std::move(*epoch_vault_id),
            .epoch_id = std::move(*epoch_id),
            .epoch_issued_at = *epoch_issued_at,
            .epoch_min_history_depth = *epoch_min_history_depth,
            .epoch_min_history_age_hours = *epoch_min_history_age_hours,
        };
        record.plan.target_generation = *target;

        auto count = wire::read<std::uint32_t>(reader);
        if (!count) {
            return std::unexpected("truncated at operation count");
        }
        // Even an operation with empty strings occupies 32 wire bytes.
        if (*count > maximum_operation_count ||
            *count > reader.data.size() / 32) {
            return std::unexpected("operation count exceeds limit");
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
            kasumi::PhysicalFileIdentity source_identity{};
            if (*version >= 10 && action_raw && *action_raw == 11) {
                auto volume = wire::read<std::uint64_t>(reader);
                auto low = wire::read<std::uint64_t>(reader);
                auto high = wire::read<std::uint64_t>(reader);
                auto id_valid = wire::read<std::uint8_t>(reader);
                if (!volume || !low || !high || !id_valid || *id_valid != 1) {
                    return std::unexpected(
                        "invalid disposable source identity");
                }
                source_identity = {
                    .volume_or_dev = *volume,
                    .file_id_low = *low,
                    .file_id_high = *high,
                    .valid = true,
                };
            }
            auto previous_hash = wire::read_string(reader, maximum_string_size);
            auto backup = wire::read<std::uint32_t>(reader);
            auto state_raw = wire::read<std::uint8_t>(reader);
            auto had_original = wire::read<std::uint8_t>(reader);

            if (!action_raw || !path || !alt_path || !hash || !size ||
                !exclusive || !previous_hash || !backup || !state_raw ||
                !had_original) {
                return std::unexpected("truncated operation");
            }
            const auto action = action_from_persisted_id(*action_raw);
            if (!action || (*version == 9 && *action_raw == 11)) {
                return std::unexpected("invalid action");
            }
            if (*exclusive > 1 || *had_original > 1) {
                return std::unexpected("invalid boolean");
            }

            const auto state = static_cast<OperationState>(*state_raw);
            if (!valid(state)) {
                return std::unexpected("invalid state");
            }

            record.plan.operations.push_back(kasumi::Operation{
                .action = *action,
                .path = platform::path::from_utf8(*path),
                .hash = std::move(*hash),
                .alt_path = platform::path::from_utf8(*alt_path),
                .size = *size,
                .exclusive_destination = *exclusive == 1,
                .expected_source_identity = source_identity,
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
            return std::unexpected("invalid canonical order");
        }

        rebuild_sync_plan_offsets(record.plan);
        if (!reader.data.empty()) {
            return std::unexpected("trailing bytes after record completion");
        }
        if (!valid(record)) {
            return std::unexpected("invalid record");
        }
        return record;
    } catch (const std::exception& exception) {
        return std::unexpected(
            std::string{"failed to decode transaction record: "} +
            exception.what());
    }
}

} // namespace kasumi::transaction::codec
