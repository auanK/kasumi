#include "core/transaction/codec.hpp"
#include "core/transaction/types.hpp"
#include "core/wire.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <iterator>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using kasumi::Action;
using kasumi::Operation;
using kasumi::SyncPlan;
using kasumi::transaction::OperationState;
using kasumi::transaction::Phase;
using kasumi::transaction::Record;

constexpr std::array actions{
    Action::RenameLocal,
    Action::Upload,
    Action::CreateLocalDirectory,
    Action::CreateRemoteDirectory,
    Action::MoveLocal,
    Action::Download,
    Action::DeleteLocal,
    Action::DeleteLocalDirectory,
    Action::DeleteRemote,
    Action::DeleteRemoteDirectory,
};

SyncPlan plan_with_all_actions() {
    std::vector<Operation> operations;
    operations.reserve(actions.size());
    for (const auto action : actions) {
        Operation operation{
            .action = action,
            .path = "path-" + std::to_string(kasumi::action_index(action)),
            .hash = "hash-" + std::to_string(kasumi::action_index(action)),
            .alt_path =
                (action == Action::RenameLocal || action == Action::MoveLocal)
                    ? "old-path"
                    : "",
            .size = 100 + kasumi::action_index(action),
            .exclusive_destination = action == Action::Upload,
        };
        operations.push_back(std::move(operation));
    }
    return kasumi::make_sync_plan(std::move(operations), 77);
}

Record representative_record() {
    auto result = kasumi::transaction::make_record(
        std::string(32, '0'), 10, 76, plan_with_all_actions());
    EXPECT_TRUE(result.has_value());
    auto record = std::move(*result);
    record.phase = Phase::HeadVerified;
    record.commit_id = std::string(64, 'a');
    record.ciphertext_id = std::string(64, 'b');
    record.parent_ids = {std::string(64, 'c')};
    record.marker_id = std::string(64, 'e');
    for (std::size_t index = 0; index < record.progress.size(); ++index) {
        record.progress[index].previous_hash =
            "previous-" + std::to_string(index);
        record.progress[index].state = OperationState::Prepared;
        record.progress[index].had_original =
            kasumi::is_local_mutation(record.plan.operations[index].action);
    }
    return record;
}

std::vector<std::byte> writer_bytes(const wire::Writer& writer) {
    return writer.buffer;
}

std::vector<std::byte> minimal_record(std::uint8_t phase,
                                      std::uint8_t action,
                                      std::uint8_t state,
                                      std::uint32_t backup_slot) {
    wire::Writer writer;
    wire::write<std::uint8_t>(writer, 9);
    wire::write_string(writer, "id");
    wire::write<std::uint8_t>(writer, phase);
    wire::write<std::uint8_t>(writer, 1);
    wire::write_string(writer, "");
    wire::write_string(writer, "");
    wire::write<std::uint64_t>(writer, 1);
    wire::write<std::uint64_t>(writer, 2);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint64_t>(writer, 3);
    wire::write_string(writer,
                       phase >= static_cast<std::uint8_t>(Phase::CommitPrepared)
                           ? std::string(64, '0')
                           : std::string{});
    wire::write_string(writer, std::string{});
    wire::write_string(writer, std::string{});
    wire::write_string(writer, std::string{});
    wire::write_string(writer, std::string{});
    wire::write<std::int64_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 1);
    wire::write<std::uint8_t>(writer, action);
    wire::write_string(writer, "path");
    wire::write_string(writer, "");
    wire::write_string(writer, "hash");
    wire::write<std::uint64_t>(writer, 1);
    wire::write<std::uint8_t>(writer, 0);
    wire::write_string(writer, "previous");
    wire::write<std::uint32_t>(writer, backup_slot);
    wire::write<std::uint8_t>(writer, state);
    wire::write<std::uint8_t>(writer, 0);
    return writer_bytes(writer);
}

struct WireOperationSpec {
    std::uint8_t wire_action = 0;
    std::string path;
    std::string alt_path;
    std::string hash;
    std::uint64_t size = 0;
    bool exclusive_destination = false;
    std::string previous_hash;
    std::uint32_t backup_slot = 0;
    std::uint8_t state = 0;
    bool had_original = false;
};

std::vector<std::byte>
build_wire_record_with_operations(std::span<const WireOperationSpec> ops) {
    wire::Writer writer;
    wire::write<std::uint8_t>(writer, 9);
    wire::write_string(writer, std::string(32, '0'));
    wire::write<std::uint8_t>(writer,
                              static_cast<std::uint8_t>(Phase::Started));
    wire::write<std::uint8_t>(writer, 1);
    wire::write_string(writer, "");
    wire::write_string(writer, "");
    wire::write<std::uint64_t>(writer, 10);
    wire::write<std::uint64_t>(writer, 76);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint64_t>(writer, 77);
    wire::write_string(writer, "");
    wire::write_string(writer, "");
    wire::write_string(writer, "");
    wire::write_string(writer, "");
    wire::write_string(writer, "");
    wire::write<std::int64_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint32_t>(writer, static_cast<std::uint32_t>(ops.size()));
    for (const auto& op : ops) {
        wire::write<std::uint8_t>(writer, op.wire_action);
        wire::write_string(writer, op.path);
        wire::write_string(writer, op.alt_path);
        wire::write_string(writer, op.hash);
        wire::write<std::uint64_t>(writer, op.size);
        wire::write<std::uint8_t>(writer, op.exclusive_destination ? 1 : 0);
        wire::write_string(writer, op.previous_hash);
        wire::write<std::uint32_t>(writer, op.backup_slot);
        wire::write<std::uint8_t>(writer, op.state);
        wire::write<std::uint8_t>(writer, op.had_original ? 1 : 0);
    }
    return writer_bytes(writer);
}

std::vector<std::uint8_t>
extract_persisted_action_bytes(std::span<const std::byte> data) {
    wire::Reader reader{data};
    (void)wire::read<std::uint8_t>(reader);
    (void)wire::read_string(reader, 4096);
    (void)wire::read<std::uint8_t>(reader);
    (void)wire::read<std::uint8_t>(reader);
    (void)wire::read_string(reader, 4096);
    (void)wire::read_string(reader, 4096);
    (void)wire::read<std::uint64_t>(reader);
    (void)wire::read<std::uint64_t>(reader);
    for (int list_idx = 0; list_idx < 2; ++list_idx) {
        const auto count = wire::read<std::uint32_t>(reader);
        if (!count) {
            return {};
        }
        for (std::uint32_t i = 0; i < *count; ++i) {
            (void)wire::read_string(reader, 4096);
        }
    }
    (void)wire::read<std::uint64_t>(reader);
    for (int str_idx = 0; str_idx < 5; ++str_idx) {
        (void)wire::read_string(reader, 4096);
    }
    (void)wire::read<std::int64_t>(reader);
    (void)wire::read<std::uint32_t>(reader);
    (void)wire::read<std::uint32_t>(reader);
    const auto parents = wire::read<std::uint32_t>(reader);
    if (!parents) {
        return {};
    }
    for (std::uint32_t i = 0; i < *parents; ++i) {
        (void)wire::read_string(reader, 4096);
    }
    const auto op_count = wire::read<std::uint32_t>(reader);
    if (!op_count) {
        return {};
    }
    std::vector<std::uint8_t> result;
    result.reserve(*op_count);
    for (std::uint32_t i = 0; i < *op_count; ++i) {
        const auto action_raw = wire::read<std::uint8_t>(reader);
        if (!action_raw) {
            return {};
        }
        result.push_back(*action_raw);
        (void)wire::read_string(reader, 4096);
        (void)wire::read_string(reader, 4096);
        (void)wire::read_string(reader, 4096);
        (void)wire::read<std::uint64_t>(reader);
        (void)wire::read<std::uint8_t>(reader);
        (void)wire::read_string(reader, 4096);
        (void)wire::read<std::uint32_t>(reader);
        (void)wire::read<std::uint8_t>(reader);
        (void)wire::read<std::uint8_t>(reader);
    }
    return result;
}

std::vector<std::byte> make_v091_all_legacy_actions_fixture() {
    const auto no_backup = std::numeric_limits<std::uint32_t>::max();
    const std::array<WireOperationSpec, 9> specs{{
        {.wire_action = 0,
         .path = "legacy-0",
         .alt_path = "old-0",
         .hash = "hash-0",
         .size = 100,
         .exclusive_destination = false,
         .previous_hash = "prev-0",
         .backup_slot = 0,
         .state = static_cast<std::uint8_t>(OperationState::Prepared),
         .had_original = true},
        {.wire_action = 1,
         .path = "legacy-1",
         .alt_path = "",
         .hash = "hash-1",
         .size = 101,
         .exclusive_destination = true,
         .previous_hash = "prev-1",
         .backup_slot = no_backup,
         .state = static_cast<std::uint8_t>(OperationState::Prepared),
         .had_original = false},
        {.wire_action = 2,
         .path = "legacy-2",
         .alt_path = "",
         .hash = "hash-2",
         .size = 102,
         .exclusive_destination = false,
         .previous_hash = "prev-2",
         .backup_slot = 1,
         .state = static_cast<std::uint8_t>(OperationState::Prepared),
         .had_original = true},
        {.wire_action = 3,
         .path = "legacy-3",
         .alt_path = "",
         .hash = "hash-3",
         .size = 103,
         .exclusive_destination = false,
         .previous_hash = "prev-3",
         .backup_slot = no_backup,
         .state = static_cast<std::uint8_t>(OperationState::Prepared),
         .had_original = false},
        {.wire_action = 4,
         .path = "legacy-4",
         .alt_path = "",
         .hash = "hash-4",
         .size = 104,
         .exclusive_destination = false,
         .previous_hash = "prev-4",
         .backup_slot = 2,
         .state = static_cast<std::uint8_t>(OperationState::Prepared),
         .had_original = true},
        {.wire_action = 5,
         .path = "legacy-5",
         .alt_path = "",
         .hash = "hash-5",
         .size = 105,
         .exclusive_destination = false,
         .previous_hash = "prev-5",
         .backup_slot = 3,
         .state = static_cast<std::uint8_t>(OperationState::Prepared),
         .had_original = true},
        {.wire_action = 6,
         .path = "legacy-6",
         .alt_path = "",
         .hash = "hash-6",
         .size = 106,
         .exclusive_destination = false,
         .previous_hash = "prev-6",
         .backup_slot = 4,
         .state = static_cast<std::uint8_t>(OperationState::Prepared),
         .had_original = true},
        {.wire_action = 7,
         .path = "legacy-7",
         .alt_path = "",
         .hash = "hash-7",
         .size = 107,
         .exclusive_destination = false,
         .previous_hash = "prev-7",
         .backup_slot = no_backup,
         .state = static_cast<std::uint8_t>(OperationState::Prepared),
         .had_original = false},
        {.wire_action = 8,
         .path = "legacy-8",
         .alt_path = "",
         .hash = "hash-8",
         .size = 108,
         .exclusive_destination = false,
         .previous_hash = "prev-8",
         .backup_slot = no_backup,
         .state = static_cast<std::uint8_t>(OperationState::Prepared),
         .had_original = false},
    }};
    return build_wire_record_with_operations(specs);
}

TEST(TransactionTypesTest,
     CreatesEmptyAndPopulatedRecordsWithCanonicalProgress) {
    const auto empty = *kasumi::transaction::make_record(
        std::string(32, '1'), 0, 0, kasumi::make_sync_plan({}, 1));
    EXPECT_FALSE(empty.operation_id.empty());
    EXPECT_TRUE(kasumi::sync_plan_empty(empty.plan));
    EXPECT_TRUE(empty.progress.empty());
    EXPECT_TRUE(kasumi::transaction::valid(empty));

    const auto record = representative_record();
    ASSERT_EQ(kasumi::sync_plan_size(record.plan), actions.size());
    ASSERT_EQ(record.progress.size(), actions.size());
    EXPECT_TRUE(kasumi::transaction::valid(record));
    for (std::size_t index = 0; index < kasumi::sync_plan_size(record.plan);
         ++index) {
        const auto expected =
            kasumi::is_local_mutation(record.plan.operations[index].action)
                ? static_cast<std::uint32_t>(std::count_if(
                      record.plan.operations.begin(),
                      record.plan.operations.begin() +
                          static_cast<std::ptrdiff_t>(index),
                      [](const auto& operation) {
                          return kasumi::is_local_mutation(operation.action);
                      }))
                : std::numeric_limits<std::uint32_t>::max();
        EXPECT_EQ(record.progress[index].backup_slot, expected);
    }
}

TEST(TransactionTypesTest, ValidatesEnumBoundariesAndOutOfRangeValues) {
    for (const auto phase : {Phase::Started,
                             Phase::FilesStaged,
                             Phase::LocalChangesApplied,
                             Phase::CommitPrepared,
                             Phase::CommitUploaded,
                             Phase::CommitVerified,
                             Phase::HeadPublished,
                             Phase::HeadVerified,
                             Phase::EpochPrepared,
                             Phase::EpochUploaded,
                             Phase::EpochVerified,
                             Phase::DatabaseCommitted,
                             Phase::CleanupCompleted}) {
        EXPECT_TRUE(kasumi::transaction::valid(phase));
    }
    EXPECT_FALSE(kasumi::transaction::valid(static_cast<Phase>(13)));
    EXPECT_FALSE(kasumi::transaction::valid(static_cast<Phase>(255)));

    EXPECT_TRUE(kasumi::transaction::valid(OperationState::Pending));
    EXPECT_TRUE(kasumi::transaction::valid(OperationState::Applied));
    EXPECT_FALSE(kasumi::transaction::valid(static_cast<OperationState>(7)));
    EXPECT_FALSE(kasumi::transaction::valid(static_cast<OperationState>(255)));
}

TEST(TransactionTypesTest, LocalOnlyRecordsHaveNoPublicationPhases) {
    auto created =
        kasumi::transaction::make_record(std::string(32, 'd'),
                                         0,
                                         0,
                                         kasumi::make_sync_plan({}, 0),
                                         false,
                                         std::string(64, 'e'));
    ASSERT_TRUE(created.has_value());

    for (const auto phase : {Phase::Started,
                             Phase::FilesStaged,
                             Phase::LocalChangesApplied,
                             Phase::DatabaseCommitted,
                             Phase::CleanupCompleted}) {
        auto record = *created;
        record.phase = phase;
        EXPECT_TRUE(kasumi::transaction::valid(record));
    }

    for (const auto phase : {Phase::CommitPrepared,
                             Phase::CommitUploaded,
                             Phase::CommitVerified,
                             Phase::HeadPublished,
                             Phase::HeadVerified,
                             Phase::EpochPrepared,
                             Phase::EpochUploaded,
                             Phase::EpochVerified}) {
        auto record = *created;
        record.phase = phase;
        EXPECT_FALSE(kasumi::transaction::valid(record));
    }
}

TEST(TransactionTypesTest, PublicationRecordsPersistObservedBaseIdentity) {
    const auto observed_head = std::string(64, 'e');
    auto record =
        kasumi::transaction::make_record(std::string(32, 'f'),
                                         0,
                                         0,
                                         kasumi::make_sync_plan({}, 0),
                                         true,
                                         observed_head);
    ASSERT_TRUE(record.has_value());
    EXPECT_TRUE(kasumi::transaction::valid(*record));

    const auto encoded = kasumi::transaction::codec::encode(*record);
    ASSERT_TRUE(encoded.has_value());
    const auto decoded = kasumi::transaction::codec::decode(*encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->observed_head_id, observed_head);
}

TEST(TransactionTypesTest, DetectsEveryKnownStructuralCorruption) {
    const auto canonical = representative_record();

    auto progress_size = canonical;
    progress_size.progress.pop_back();
    EXPECT_FALSE(kasumi::transaction::valid(progress_size));

    auto offsets = canonical;
    offsets.plan.offsets[2] = 0;
    EXPECT_FALSE(kasumi::transaction::valid(offsets));

    auto invalid_action = canonical;
    invalid_action.plan.operations.front().action = Action::Count;
    EXPECT_FALSE(kasumi::transaction::valid(invalid_action));

    auto duplicate_backup = canonical;
    const auto first_local =
        std::find_if(duplicate_backup.plan.operations.begin(),
                     duplicate_backup.plan.operations.end(),
                     [](const auto& operation) {
                         return kasumi::is_local_mutation(operation.action);
                     });
    ASSERT_NE(first_local, duplicate_backup.plan.operations.end());
    const auto first_index = static_cast<std::size_t>(
        std::distance(duplicate_backup.plan.operations.begin(), first_local));
    auto second_local =
        std::find_if(first_local + 1,
                     duplicate_backup.plan.operations.end(),
                     [](const auto& operation) {
                         return kasumi::is_local_mutation(operation.action);
                     });
    ASSERT_NE(second_local, duplicate_backup.plan.operations.end());
    const auto second_index = static_cast<std::size_t>(
        std::distance(duplicate_backup.plan.operations.begin(), second_local));
    duplicate_backup.progress[second_index].backup_slot =
        duplicate_backup.progress[first_index].backup_slot;
    EXPECT_FALSE(kasumi::transaction::valid(duplicate_backup));

    auto nonlocal_backup = canonical;
    const auto nonlocal =
        std::find_if(nonlocal_backup.plan.operations.begin(),
                     nonlocal_backup.plan.operations.end(),
                     [](const auto& operation) {
                         return !kasumi::is_local_mutation(operation.action);
                     });
    ASSERT_NE(nonlocal, nonlocal_backup.plan.operations.end());
    const auto nonlocal_index = static_cast<std::size_t>(
        std::distance(nonlocal_backup.plan.operations.begin(), nonlocal));
    nonlocal_backup.progress[nonlocal_index].backup_slot = 0;
    EXPECT_FALSE(kasumi::transaction::valid(nonlocal_backup));

    auto invalid_phase = canonical;
    invalid_phase.phase = static_cast<Phase>(13);
    EXPECT_FALSE(kasumi::transaction::valid(invalid_phase));

    auto invalid_state = canonical;
    invalid_state.progress.front().state = static_cast<OperationState>(7);
    EXPECT_FALSE(kasumi::transaction::valid(invalid_state));
}

TEST(TransactionCodecTest, RoundTripsAllActionsAndProgressFields) {
    const auto original = representative_record();
    const auto encoded = kasumi::transaction::codec::encode(original);
    ASSERT_TRUE(encoded.has_value());

    const auto decoded = kasumi::transaction::codec::decode(*encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->operation_id, original.operation_id);
    EXPECT_EQ(decoded->phase, original.phase);
    EXPECT_EQ(decoded->publication_required, original.publication_required);
    EXPECT_EQ(decoded->observed_head_id, original.observed_head_id);
    EXPECT_EQ(decoded->observed_base_id, original.observed_base_id);
    EXPECT_EQ(decoded->observed_pending_paths, original.observed_pending_paths);
    EXPECT_EQ(decoded->pending_paths, original.pending_paths);
    EXPECT_EQ(decoded->local_generation, original.local_generation);
    EXPECT_EQ(decoded->storage_generation, original.storage_generation);
    EXPECT_EQ(decoded->commit_id, original.commit_id);
    EXPECT_EQ(decoded->ciphertext_id, original.ciphertext_id);
    EXPECT_EQ(decoded->parent_ids, original.parent_ids);
    EXPECT_EQ(decoded->marker_id, original.marker_id);
    EXPECT_EQ(decoded->plan.target_generation, original.plan.target_generation);
    ASSERT_EQ(decoded->plan.operations.size(), original.plan.operations.size());
    ASSERT_EQ(decoded->progress.size(), original.progress.size());
    for (std::size_t index = 0; index < original.plan.operations.size();
         ++index) {
        EXPECT_EQ(decoded->plan.operations[index].action,
                  original.plan.operations[index].action);
        EXPECT_EQ(decoded->plan.operations[index].path,
                  original.plan.operations[index].path);
        EXPECT_EQ(decoded->plan.operations[index].alt_path,
                  original.plan.operations[index].alt_path);
        EXPECT_EQ(decoded->plan.operations[index].hash,
                  original.plan.operations[index].hash);
        EXPECT_EQ(decoded->plan.operations[index].size,
                  original.plan.operations[index].size);
        EXPECT_EQ(decoded->plan.operations[index].exclusive_destination,
                  original.plan.operations[index].exclusive_destination);
        EXPECT_EQ(decoded->progress[index].previous_hash,
                  original.progress[index].previous_hash);
        EXPECT_EQ(decoded->progress[index].backup_slot,
                  original.progress[index].backup_slot);
        EXPECT_EQ(decoded->progress[index].state,
                  original.progress[index].state);
        EXPECT_EQ(decoded->progress[index].had_original,
                  original.progress[index].had_original);
    }
}

TEST(TransactionCodecTest, UnicodeOperationPathsRoundTrip) {
    constexpr std::array<std::string_view, 6> paths{
        "高松灯/カード💝.png",
        "千早愛音/Karyl🌸.png",
        "Icons/𝑬𝒎𝒊𝒍𝒊𝒂.txt",
        "Icons/𓆩🌸𓆪.txt",
        "pasta-日本/usuário-☁.txt",
        "Ä/ä.txt",
    };

    auto original = representative_record();
    for (std::size_t index = 0; index < original.plan.operations.size();
         ++index) {
        auto& operation = original.plan.operations[index];
        operation.path =
            kasumi::platform::path::from_utf8(paths[index % paths.size()]);
        operation.alt_path = kasumi::platform::path::from_utf8(
            paths[(index + 1) % paths.size()]);
    }

    const auto encoded = kasumi::transaction::codec::encode(original);
    ASSERT_TRUE(encoded.has_value()) << encoded.error();
    const auto decoded = kasumi::transaction::codec::decode(*encoded);
    ASSERT_TRUE(decoded.has_value()) << decoded.error();
    ASSERT_EQ(decoded->plan.operations.size(), original.plan.operations.size());
    for (std::size_t index = 0; index < decoded->plan.operations.size();
         ++index) {
        const auto& operation = decoded->plan.operations[index];
        EXPECT_EQ(kasumi::platform::path::to_logical_utf8(operation.path),
                  paths[index % paths.size()]);
        EXPECT_EQ(kasumi::platform::path::to_logical_utf8(operation.alt_path),
                  paths[(index + 1) % paths.size()]);
        EXPECT_EQ(operation.path, original.plan.operations[index].path);
        EXPECT_EQ(operation.alt_path, original.plan.operations[index].alt_path);
    }
    const auto reencoded = kasumi::transaction::codec::encode(*decoded);
    ASSERT_TRUE(reencoded.has_value()) << reencoded.error();
    EXPECT_EQ(*reencoded, *encoded);
}

TEST(TransactionCodecTest, UnicodeOperationPathLimitsUseUtf8Bytes) {
    std::string logical_path;
    for (std::size_t index = 0; index < 1024; ++index) {
        logical_path += "🌸";
    }
    ASSERT_EQ(logical_path.size(), 4096U);
    for (const bool alternate : {false, true}) {
        SCOPED_TRACE(alternate);
        auto record = representative_record();
        auto& operation = record.plan.operations.front();
        auto& path = alternate ? operation.alt_path : operation.path;
        path = kasumi::platform::path::from_utf8(logical_path);
        const auto encoded = kasumi::transaction::codec::encode(record);
        ASSERT_TRUE(encoded.has_value()) << encoded.error();
        const auto decoded = kasumi::transaction::codec::decode(*encoded);
        ASSERT_TRUE(decoded.has_value()) << decoded.error();
        path = kasumi::platform::path::from_utf8(logical_path + "🌸");
        EXPECT_FALSE(kasumi::transaction::codec::encode(record).has_value());
    }
}

TEST(TransactionCodecTest, RoundTripsLocalOnlyMaterializationRecord) {
    const auto plan =
        kasumi::make_sync_plan({Operation{.action = Action::Download,
                                          .path = "file.txt",
                                          .hash = std::string(64, 'a'),
                                          .alt_path = {},
                                          .size = 4}},
                               7);
    auto record = kasumi::transaction::make_record(
        std::string(32, '2'), 1, 7, plan, false, std::string(64, 'b'));
    ASSERT_TRUE(record.has_value());
    record->phase = Phase::LocalChangesApplied;
    record->observed_base_id = std::string(64, 'c');
    record->observed_pending_paths = {"docs/a.txt"};
    record->pending_paths = {"docs/b.txt", "other.txt"};
    record->progress[0].state = OperationState::Applied;
    const auto encoded = kasumi::transaction::codec::encode(*record);
    ASSERT_TRUE(encoded.has_value());
    const auto decoded = kasumi::transaction::codec::decode(*encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_FALSE(decoded->publication_required);
    EXPECT_EQ(decoded->observed_head_id, std::string(64, 'b'));
    EXPECT_EQ(decoded->observed_base_id, std::string(64, 'c'));
    EXPECT_EQ(decoded->observed_pending_paths,
              (std::vector<std::string>{"docs/a.txt"}));
    EXPECT_EQ(decoded->pending_paths,
              (std::vector<std::string>{"docs/b.txt", "other.txt"}));
    EXPECT_EQ(decoded->plan.target_generation, 7U);
    EXPECT_EQ(decoded->phase, Phase::LocalChangesApplied);
}

TEST(TransactionCodecTest, RoundTripsGenesisEpochCheckpoint) {
    auto record = kasumi::transaction::make_record(
        std::string(32, '3'), 0, 0, kasumi::make_sync_plan({}, 0));
    ASSERT_TRUE(record.has_value());
    record->phase = Phase::EpochVerified;
    record->commit_id = std::string(64, 'a');
    record->ciphertext_id = std::string(64, 'b');
    record->marker_id = std::string(64, 'e');
    record->epoch_vault_id = std::string(64, 'c');
    record->epoch_id = std::string(64, 'd');
    record->epoch_issued_at = 123;
    record->epoch_min_history_depth = 2;
    record->epoch_min_history_age_hours = 6;

    const auto encoded = kasumi::transaction::codec::encode(*record);
    ASSERT_TRUE(encoded.has_value());
    const auto decoded = kasumi::transaction::codec::decode(*encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->phase, Phase::EpochVerified);
    EXPECT_EQ(decoded->epoch_vault_id, record->epoch_vault_id);
    EXPECT_EQ(decoded->epoch_id, record->epoch_id);
    EXPECT_EQ(decoded->epoch_issued_at, 123);
    EXPECT_EQ(decoded->epoch_min_history_depth, 2U);
    EXPECT_EQ(decoded->epoch_min_history_age_hours, 6U);
}

TEST(TransactionCodecTest, RejectsPublicationPhasesInLocalOnlyRecords) {
    auto record =
        kasumi::transaction::make_record(std::string(32, 'f'),
                                         0,
                                         0,
                                         kasumi::make_sync_plan({}, 0),
                                         false,
                                         std::string(64, 'a'));
    ASSERT_TRUE(record.has_value());
    for (const auto phase : {Phase::CommitPrepared,
                             Phase::CommitUploaded,
                             Phase::CommitVerified,
                             Phase::HeadPublished,
                             Phase::HeadVerified,
                             Phase::EpochPrepared,
                             Phase::EpochUploaded,
                             Phase::EpochVerified}) {
        record->phase = phase;
        EXPECT_FALSE(kasumi::transaction::codec::encode(*record).has_value());
    }
}

TEST(TransactionCodecTest, DecoderRejectsPersistedPublicationPhaseInLocalOnly) {
    auto record =
        kasumi::transaction::make_record(std::string(32, 'c'),
                                         0,
                                         0,
                                         kasumi::make_sync_plan({}, 0),
                                         false,
                                         std::string(64, 'a'));
    ASSERT_TRUE(record.has_value());
    const auto encoded = kasumi::transaction::codec::encode(*record);
    ASSERT_TRUE(encoded.has_value());

    constexpr std::size_t phase_offset = 1 + sizeof(std::uint32_t) + 32;
    ASSERT_LT(phase_offset, encoded->size());
    for (const auto phase : {Phase::CommitPrepared,
                             Phase::CommitUploaded,
                             Phase::CommitVerified,
                             Phase::HeadPublished,
                             Phase::HeadVerified,
                             Phase::EpochPrepared,
                             Phase::EpochUploaded,
                             Phase::EpochVerified}) {
        auto corrupted = *encoded;
        corrupted[phase_offset] =
            static_cast<std::byte>(static_cast<std::uint8_t>(phase));
        EXPECT_FALSE(kasumi::transaction::codec::decode(corrupted).has_value())
            << static_cast<unsigned>(static_cast<std::uint8_t>(phase));
    }
}

TEST(TransactionCodecTest, HandlesEmptyStringsAndRejectsOversizedStrings) {
    auto empty_strings = representative_record();
    empty_strings.commit_id = std::string(64, '0');
    for (auto& operation : empty_strings.plan.operations) {
        operation.path.clear();
        operation.hash.clear();
        operation.alt_path.clear();
    }
    const auto encoded = kasumi::transaction::codec::encode(empty_strings);
    ASSERT_TRUE(encoded.has_value());
    EXPECT_TRUE(kasumi::transaction::codec::decode(*encoded).has_value());

    auto oversized = representative_record();
    oversized.operation_id.assign(4097, 'x');
    const auto oversized_encoded =
        kasumi::transaction::codec::encode(oversized);
    EXPECT_FALSE(oversized_encoded.has_value());
}

TEST(TransactionCodecTest, RejectsEveryTruncatedEncoding) {
    const auto encoded =
        kasumi::transaction::codec::encode(representative_record());
    ASSERT_TRUE(encoded.has_value());
    for (std::size_t cut = 0; cut < encoded->size(); ++cut) {
        SCOPED_TRACE(cut);
        const auto decoded = kasumi::transaction::codec::decode(
            std::span<const std::byte>{encoded->data(), cut});
        EXPECT_FALSE(decoded.has_value());
    }
}

TEST(TransactionCodecTest, RejectsInvalidEnumsAndInvalidRecords) {
    const auto invalid_phase = minimal_record(255, 0, 0, 0);
    EXPECT_FALSE(kasumi::transaction::codec::decode(invalid_phase).has_value());

    const auto invalid_action =
        minimal_record(static_cast<std::uint8_t>(Phase::Started),
                       static_cast<std::uint8_t>(Action::Count),
                       0,
                       std::numeric_limits<std::uint32_t>::max());
    EXPECT_FALSE(
        kasumi::transaction::codec::decode(invalid_action).has_value());

    const auto invalid_state =
        minimal_record(static_cast<std::uint8_t>(Phase::Started),
                       static_cast<std::uint8_t>(Action::Upload),
                       255,
                       std::numeric_limits<std::uint32_t>::max());
    EXPECT_FALSE(kasumi::transaction::codec::decode(invalid_state).has_value());

    auto invalid_record = representative_record();
    invalid_record.progress.pop_back();
    EXPECT_FALSE(
        kasumi::transaction::codec::encode(invalid_record).has_value());

    auto invalid_pending = representative_record();
    invalid_pending.pending_paths = {"../outside"};
    EXPECT_FALSE(
        kasumi::transaction::codec::encode(invalid_pending).has_value());
    invalid_pending = representative_record();
    invalid_pending.pending_paths = {"same.txt", "same.txt"};
    EXPECT_FALSE(
        kasumi::transaction::codec::encode(invalid_pending).has_value());
}

// Teste A — Identificadores históricos (0..8)
TEST(TransactionCodecTest, EncodesHistoricalV091ActionIdentifiers) {
    constexpr std::array<std::pair<Action, std::uint8_t>, 9> legacy_mapping{{
        {Action::RenameLocal, 0U},
        {Action::Upload, 1U},
        {Action::CreateLocalDirectory, 2U},
        {Action::CreateRemoteDirectory, 3U},
        {Action::Download, 4U},
        {Action::DeleteLocal, 5U},
        {Action::DeleteLocalDirectory, 6U},
        {Action::DeleteRemote, 7U},
        {Action::DeleteRemoteDirectory, 8U},
    }};

    std::vector<Operation> operations;
    operations.reserve(legacy_mapping.size());
    for (std::size_t idx = 0; idx < legacy_mapping.size(); ++idx) {
        const auto action = legacy_mapping[idx].first;
        operations.push_back(Operation{
            .action = action,
            .path = "legacy-" + std::to_string(idx),
            .hash = "hash-" + std::to_string(idx),
            .alt_path = action == Action::RenameLocal ? "old-0" : "",
            .size = 100 + idx,
            .exclusive_destination = action == Action::Upload,
        });
    }

    auto record = kasumi::transaction::make_record(
        std::string(32, '0'),
        10,
        76,
        kasumi::make_sync_plan(std::move(operations), 77));
    ASSERT_TRUE(record.has_value());

    const auto encoded = kasumi::transaction::codec::encode(*record);
    ASSERT_TRUE(encoded.has_value()) << encoded.error();

    const auto persisted_ids = extract_persisted_action_bytes(*encoded);
    ASSERT_EQ(persisted_ids.size(), legacy_mapping.size());
    for (std::size_t idx = 0; idx < legacy_mapping.size(); ++idx) {
        EXPECT_EQ(persisted_ids[idx], legacy_mapping[idx].second)
            << "Action mismatch at index " << idx;
    }
}

// Teste B — Decode de registros produzidos pela v0.9.1
TEST(TransactionCodecTest,
     DecodesHistoricalV091WireBytesWithoutConfusingDownloadWithMoveLocal) {
    const auto v091_bytes = make_v091_all_legacy_actions_fixture();
    const auto decoded = kasumi::transaction::codec::decode(v091_bytes);
    ASSERT_TRUE(decoded.has_value()) << decoded.error();
    ASSERT_EQ(decoded->plan.operations.size(), 9U);

    EXPECT_EQ(decoded->plan.operations[0].action, Action::RenameLocal);
    EXPECT_EQ(decoded->plan.operations[1].action, Action::Upload);
    EXPECT_EQ(decoded->plan.operations[2].action, Action::CreateLocalDirectory);
    EXPECT_EQ(decoded->plan.operations[3].action,
              Action::CreateRemoteDirectory);
    EXPECT_EQ(decoded->plan.operations[4].action, Action::Download);
    EXPECT_NE(decoded->plan.operations[4].action, Action::MoveLocal);
    EXPECT_EQ(decoded->plan.operations[5].action, Action::DeleteLocal);
    EXPECT_EQ(decoded->plan.operations[6].action, Action::DeleteLocalDirectory);
    EXPECT_EQ(decoded->plan.operations[7].action, Action::DeleteRemote);
    EXPECT_EQ(decoded->plan.operations[8].action,
              Action::DeleteRemoteDirectory);
}

// Teste C — MoveLocal novo (identificador persistido = 9)
TEST(TransactionCodecTest,
     EncodesMoveLocalAsWireIdentifierNineAndRoundTripsFields) {
    const auto hash_hex = std::string(64, 'a');
    auto record = kasumi::transaction::make_record(
        std::string(32, '4'),
        2,
        5,
        kasumi::make_sync_plan(
            {Operation{.action = Action::MoveLocal,
                       .path = "Haruka/src/main.cpp",
                       .hash = hash_hex,
                       .alt_path = "HarukaEngine/src/main.cpp",
                       .size = 4096,
                       .exclusive_destination = false}},
            6));
    ASSERT_TRUE(record.has_value());
    record->progress[0].previous_hash = hash_hex;
    record->progress[0].backup_slot = 0;
    record->progress[0].state = OperationState::BackupCreated;
    record->progress[0].had_original = true;

    EXPECT_EQ(kasumi::action_index(Action::MoveLocal), 4U);

    const auto encoded = kasumi::transaction::codec::encode(*record);
    ASSERT_TRUE(encoded.has_value()) << encoded.error();

    const auto persisted_ids = extract_persisted_action_bytes(*encoded);
    ASSERT_EQ(persisted_ids.size(), 1U);
    EXPECT_EQ(persisted_ids[0], 9U);

    const auto decoded = kasumi::transaction::codec::decode(*encoded);
    ASSERT_TRUE(decoded.has_value()) << decoded.error();
    ASSERT_EQ(decoded->plan.operations.size(), 1U);
    const auto& op = decoded->plan.operations[0];
    const auto& prog = decoded->progress[0];
    EXPECT_EQ(op.action, Action::MoveLocal);
    EXPECT_EQ(kasumi::platform::path::to_logical_utf8(op.path),
              "Haruka/src/main.cpp");
    EXPECT_EQ(kasumi::platform::path::to_logical_utf8(op.alt_path),
              "HarukaEngine/src/main.cpp");
    EXPECT_EQ(op.hash, hash_hex);
    EXPECT_EQ(op.size, 4096U);
    EXPECT_FALSE(op.exclusive_destination);
    EXPECT_EQ(prog.previous_hash, hash_hex);
    EXPECT_EQ(prog.backup_slot, 0U);
    EXPECT_EQ(prog.state, OperationState::BackupCreated);
    EXPECT_TRUE(prog.had_original);
}

// Teste D — Ordem canônica e offsets com ações legadas + MoveLocal
TEST(TransactionCodecTest,
     PreservesCanonicalInternalPhaseOrderAndOffsetsAcrossMoveLocalAndLegacy) {
    const auto original = representative_record();
    const auto encoded = kasumi::transaction::codec::encode(original);
    ASSERT_TRUE(encoded.has_value()) << encoded.error();

    const auto persisted_ids = extract_persisted_action_bytes(*encoded);
    const std::vector<std::uint8_t> expected_wire_sequence{
        0U, 1U, 2U, 3U, 9U, 4U, 5U, 6U, 7U, 8U};
    EXPECT_EQ(persisted_ids, expected_wire_sequence);

    const auto decoded = kasumi::transaction::codec::decode(*encoded);
    ASSERT_TRUE(decoded.has_value()) << decoded.error();
    EXPECT_EQ(decoded->plan.offsets, original.plan.offsets);
    EXPECT_EQ(decoded->plan.operations[4].action, Action::MoveLocal);
    EXPECT_EQ(decoded->plan.operations[5].action, Action::Download);
    EXPECT_EQ(kasumi::sync_plan_phase(decoded->plan, Action::MoveLocal).size(),
              1U);
    EXPECT_EQ(kasumi::sync_plan_phase(decoded->plan, Action::Download).size(),
              1U);

    // Wire ordering where Download (4) precedes MoveLocal (9) violates internal
    // canonical phase ordering (MoveLocal < Download) and must be rejected.
    const std::array<WireOperationSpec, 2> out_of_order_specs{{
        {.wire_action = 4,
         .path = "dl.bin",
         .alt_path = "",
         .hash = std::string(64, 'b'),
         .size = 10,
         .exclusive_destination = false,
         .previous_hash = "",
         .backup_slot = 0,
         .state = static_cast<std::uint8_t>(OperationState::Pending),
         .had_original = false},
        {.wire_action = 9,
         .path = "src.bin",
         .alt_path = "dst.bin",
         .hash = std::string(64, 'c'),
         .size = 20,
         .exclusive_destination = false,
         .previous_hash = "",
         .backup_slot = 1,
         .state = static_cast<std::uint8_t>(OperationState::Pending),
         .had_original = false},
    }};
    const auto out_of_order_bytes =
        build_wire_record_with_operations(out_of_order_specs);
    EXPECT_FALSE(
        kasumi::transaction::codec::decode(out_of_order_bytes).has_value());
}

// Teste E — Identificadores inválidos (10, 255) e MoveLocal inválido
TEST(TransactionCodecTest,
     RejectsUnknownActionWireIdentifiersAndInvalidMoveLocalRecords) {
    for (const std::uint8_t unknown_id :
         {std::uint8_t{10}, std::uint8_t{11}, std::uint8_t{255}}) {
        SCOPED_TRACE(static_cast<unsigned>(unknown_id));
        const auto invalid_bytes =
            minimal_record(static_cast<std::uint8_t>(Phase::Started),
                           unknown_id,
                           0,
                           std::numeric_limits<std::uint32_t>::max());
        EXPECT_FALSE(
            kasumi::transaction::codec::decode(invalid_bytes).has_value());
    }

    // MoveLocal without local-mutation backup_slot (no_backup instead of 0) or
    // with unsafe path must be rejected by record validation.
    const std::array<WireOperationSpec, 1> missing_backup_slot_spec{{
        {.wire_action = 9,
         .path = "A/1.bin",
         .alt_path = "B/1.bin",
         .hash = std::string(64, 'a'),
         .size = 16,
         .exclusive_destination = false,
         .previous_hash = "",
         .backup_slot = std::numeric_limits<std::uint32_t>::max(),
         .state = static_cast<std::uint8_t>(OperationState::Pending),
         .had_original = false},
    }};
    EXPECT_FALSE(
        kasumi::transaction::codec::decode(
            build_wire_record_with_operations(missing_backup_slot_spec))
            .has_value());

    const std::array<WireOperationSpec, 1> unsafe_alt_path_spec{{
        {.wire_action = 9,
         .path = "A/1.bin",
         .alt_path = "../outside.bin",
         .hash = std::string(64, 'a'),
         .size = 16,
         .exclusive_destination = false,
         .previous_hash = "",
         .backup_slot = 0,
         .state = static_cast<std::uint8_t>(OperationState::Pending),
         .had_original = false},
    }};
    EXPECT_FALSE(kasumi::transaction::codec::decode(
                     build_wire_record_with_operations(unsafe_alt_path_spec))
                     .has_value());
}

// Teste F — Compatibilidade de bytes antigos (decode v0.9.1 -> encode novo)
TEST(TransactionCodecTest,
     DecodingAndReencodingHistoricalV091BytesPreservesBinaryRepresentation) {
    const auto v091_bytes = make_v091_all_legacy_actions_fixture();
    const auto decoded = kasumi::transaction::codec::decode(v091_bytes);
    ASSERT_TRUE(decoded.has_value()) << decoded.error();

    const auto reencoded = kasumi::transaction::codec::encode(*decoded);
    ASSERT_TRUE(reencoded.has_value()) << reencoded.error();
    EXPECT_EQ(*reencoded, v091_bytes);
}

} // namespace
