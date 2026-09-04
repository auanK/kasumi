#include "core/transaction/codec.hpp"
#include "core/transaction/types.hpp"
#include "core/wire.hpp"

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
            .alt_path = action == Action::RenameLocal ? "old-path" : "",
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
    record.marker_id = "history/heads/" + record.commit_id + "-" +
                       record.ciphertext_id + ".head";
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
    wire::write<std::uint64_t>(writer, 1);
    wire::write<std::uint64_t>(writer, 2);
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
    record->progress[0].state = OperationState::Applied;
    const auto encoded = kasumi::transaction::codec::encode(*record);
    ASSERT_TRUE(encoded.has_value());
    const auto decoded = kasumi::transaction::codec::decode(*encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_FALSE(decoded->publication_required);
    EXPECT_EQ(decoded->observed_head_id, std::string(64, 'b'));
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
    record->marker_id = "history/heads/" + record->commit_id + "-" +
                        record->ciphertext_id + ".head";
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
}

} // namespace
