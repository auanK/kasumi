#include "application/history_storage/activity.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "transport/transport.hpp"

#include <array>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace kasumi::application::history_storage::activity {
namespace {

constexpr crypto::Key kTestKey = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
    0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};

ActivityRecord make_sample(std::string_view event_id_hex,
                           ActivityOperation op,
                           ActivityOutcome outcome,
                           std::int64_t finished_at,
                           std::uint8_t machine_fill = 0x42,
                           std::string_view machine_name = "PC-Casa") {
    std::array<std::uint8_t, machine_id_byte_count> machine_id{};
    machine_id.fill(machine_fill);
    return ActivityRecord{
        .event_id = std::string{event_id_hex},
        .operation = op,
        .outcome = outcome,
        .machine_id = machine_id,
        .machine_name = std::string{machine_name},
        .started_at = finished_at - 5,
        .finished_at = finished_at,
        .duration_ms = 5000,
        .metric_primary = 12,
        .metric_secondary = 3,
        .metric_bytes = 65536,
        .flags = flag_analysis_only,
        .stage = "finalizing",
        .detail = sanitize_text("completed\nok\n", maximum_detail_bytes),
    };
}

TEST(HistoryStorageActivityTest, CodecRoundTripsAndRejectsMalformedRecords) {
    const auto sample = make_sample("0123456789abcdef0123456789abcdef",
                                    ActivityOperation::Fsck,
                                    ActivityOutcome::Succeeded,
                                    1700000100);
    EXPECT_TRUE(valid_record(sample));
    const auto encoded = encode(sample);
    ASSERT_TRUE(encoded.has_value()) << encoded.error().detail;

    const auto decoded = decode(*encoded);
    ASSERT_TRUE(decoded.has_value()) << decoded.error().detail;
    EXPECT_EQ(*decoded, sample);

    auto bad_magic = *encoded;
    bad_magic[0] = 'X';
    EXPECT_FALSE(decode(bad_magic));

    auto bad_version = *encoded;
    bad_version[4] = 99;
    EXPECT_FALSE(decode(bad_version));

    auto trailing = *encoded;
    trailing.push_back(0);
    EXPECT_FALSE(decode(trailing));

    auto truncated = *encoded;
    truncated.pop_back();
    EXPECT_FALSE(decode(truncated));

    auto bad_record = sample;
    bad_record.started_at = bad_record.finished_at + 10;
    EXPECT_FALSE(valid_record(bad_record));
    EXPECT_FALSE(encode(bad_record));
}

TEST(HistoryStorageActivityTest,
     PublishLoadAndRejectsCorruptOrMismatchedObjects) {
    auto workspace = kasumi::test::make_temp_workspace("activity-publish-load");
    const auto remote_dir = kasumi::test::workspace_path(workspace, "remote");
    const auto scratch = kasumi::test::workspace_path(workspace, "scratch");
    std::filesystem::create_directories(remote_dir);
    std::filesystem::create_directories(scratch);

    auto storage_res = transport::open_transport(
        kasumi::platform::path::to_utf8(remote_dir), scratch);
    ASSERT_TRUE(storage_res.has_value()) << storage_res.error().message;
    auto storage = std::move(*storage_res);
    ASSERT_TRUE(transport::initialize(storage));

    const auto layout = derive_remote_layout(kTestKey);
    const auto r1 = make_sample("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                ActivityOperation::Fsck,
                                ActivityOutcome::Succeeded,
                                1700000100);
    const auto r2 = make_sample("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                ActivityOperation::GarbageCollect,
                                ActivityOutcome::IssuesFound,
                                1700000200);

    const auto id1 = publish(storage, layout, kTestKey, r1, scratch);
    const auto id2 = publish(storage, layout, kTestKey, r2, scratch);
    ASSERT_TRUE(id1.has_value()) << id1.error().detail;
    ASSERT_TRUE(id2.has_value()) << id2.error().detail;
    EXPECT_TRUE(is_activity_object(layout, *id1));
    EXPECT_FALSE(is_history_object(layout, *id1));

    const auto loaded = load_all(storage, layout, kTestKey, scratch);
    ASSERT_TRUE(loaded.has_value()) << loaded.error().detail;
    EXPECT_TRUE(loaded->invalid_objects.empty());
    ASSERT_EQ(loaded->valid.size(), 2U);
    // Ordered newest first.
    EXPECT_EQ(loaded->valid[0].record, r2);
    EXPECT_EQ(loaded->valid[1].record, r1);

    // Plant a malformed name and an encrypted History-purpose payload under
    // activity_prefix; load_all classifies both as invalid_objects.
    const auto bad_name = layout.activity_prefix + "not-an-activity";
    const auto wrong_purpose = crypto::encrypt_bytes(
        *encode(r1), kTestKey, crypto::FilePurpose::History);
    ASSERT_TRUE(wrong_purpose.has_value());
    const auto temp = scratch / "wrong_purpose.bin";
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(wrong_purpose->data()),
                  static_cast<std::streamsize>(wrong_purpose->size()));
    }
    const auto mismatched_id =
        object_identifier(
            layout, 1700000300, "cccccccccccccccccccccccccccccccc")
            .value();
    ASSERT_TRUE(transport::put(storage, temp, bad_name));
    ASSERT_TRUE(transport::put(storage, temp, mismatched_id));

    const auto reloaded = load_all(storage, layout, kTestKey, scratch);
    ASSERT_TRUE(reloaded.has_value()) << reloaded.error().detail;
    EXPECT_EQ(reloaded->valid.size(), 2U);
    EXPECT_EQ(reloaded->invalid_objects.size(), 2U);
}

TEST(HistoryStorageActivityTest,
     PlanPruningMatchesDepthAgeWindowAndPreservesLatestSuccess) {
    const auto layout = derive_remote_layout(kTestKey);
    const std::int64_t now = 1700100000;
    const epoch::RetentionPolicy policy{
        .min_history_depth = 2,
        .min_history_age_hours = 6,
    };
    const std::int64_t old = now - 7LL * 3600LL;
    const std::int64_t recent = now - 3600LL;

    auto make_loaded = [&](std::string_view hex,
                           ActivityOutcome outcome,
                           std::int64_t ts,
                           std::uint8_t machine = 0x42) {
        auto id = object_identifier(layout, ts, hex).value();
        return LoadedActivity{
            .identifier = id,
            .record =
                make_sample(hex, ActivityOperation::Fsck, outcome, ts, machine),
        };
    };

    // Machine A: 4 old runs (oldest is Succeeded, newer 3 are Failed).
    // Keep newest 2 by depth (hex3, hex2), prune hex1, KEEP hex0 (latest
    // Succeeded).
    const auto a3 = make_loaded(
        "00000000000000000000000000000003", ActivityOutcome::Failed, old + 30);
    const auto a2 = make_loaded(
        "00000000000000000000000000000002", ActivityOutcome::Failed, old + 20);
    const auto a1 = make_loaded(
        "00000000000000000000000000000001", ActivityOutcome::Failed, old + 10);
    const auto a0 = make_loaded(
        "00000000000000000000000000000000", ActivityOutcome::Succeeded, old);
    // Machine B: all 4 within age window or future clock skew -> none pruned.
    const auto b0 = make_loaded("10000000000000000000000000000000",
                                ActivityOutcome::Succeeded,
                                recent,
                                0x43);
    const auto b1 = make_loaded("10000000000000000000000000000001",
                                ActivityOutcome::Succeeded,
                                recent + 10,
                                0x43);
    const auto b2 = make_loaded("10000000000000000000000000000002",
                                ActivityOutcome::Succeeded,
                                recent + 20,
                                0x43);
    const auto b3 = make_loaded("10000000000000000000000000000003",
                                ActivityOutcome::Succeeded,
                                now + 600,
                                0x43);

    const std::vector<LoadedActivity> items{a3, a2, a1, a0, b3, b2, b1, b0};
    const auto pruned = plan_pruning(items, policy, now);
    ASSERT_EQ(pruned.size(), 1U);
    EXPECT_EQ(pruned[0], a1.identifier);
}

} // namespace
} // namespace kasumi::application::history_storage::activity
