#include "application/history_storage/remote_layout.hpp"

#include <array>
#include <gtest/gtest.h>
#include <string_view>

namespace kasumi::application::history_storage {
namespace {

constexpr crypto::Key TEST_KEY_A = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

constexpr crypto::Key TEST_KEY_B = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

TEST(RemoteLayoutTest, DeriveLayoutIsDeterministic) {
    const auto layout1 = derive_remote_layout(TEST_KEY_A);
    const auto layout2 = derive_remote_layout(TEST_KEY_A);

    EXPECT_EQ(layout1.history_prefix, layout2.history_prefix);
    EXPECT_EQ(layout1.commits_prefix, layout2.commits_prefix);
    EXPECT_EQ(layout1.heads_prefix, layout2.heads_prefix);
    EXPECT_EQ(layout1.epochs_prefix, layout2.epochs_prefix);
    EXPECT_EQ(layout1.gc_prefix, layout2.gc_prefix);
    EXPECT_EQ(layout1.barrier_identifier, layout2.barrier_identifier);
    EXPECT_EQ(layout1.writers_prefix, layout2.writers_prefix);
    EXPECT_EQ(layout1.probes_prefix, layout2.probes_prefix);
    EXPECT_EQ(layout1.quarantine_prefix, layout2.quarantine_prefix);
    EXPECT_EQ(layout1.quarantine_content_prefix,
              layout2.quarantine_content_prefix);
    EXPECT_EQ(layout1.quarantine_commits_prefix,
              layout2.quarantine_commits_prefix);
}

TEST(RemoteLayoutTest, DistinctKeysProduceDistinctLayouts) {
    const auto layout_a = derive_remote_layout(TEST_KEY_A);
    const auto layout_b = derive_remote_layout(TEST_KEY_B);

    EXPECT_NE(layout_a.history_prefix, layout_b.history_prefix);
    EXPECT_NE(layout_a.commits_prefix, layout_b.commits_prefix);
    EXPECT_NE(layout_a.heads_prefix, layout_b.heads_prefix);
    EXPECT_NE(layout_a.epochs_prefix, layout_b.epochs_prefix);
    EXPECT_NE(layout_a.barrier_identifier, layout_b.barrier_identifier);
}

TEST(RemoteLayoutTest, PrefixesAreWellFormedAndNestedUnderHistory) {
    const auto layout = derive_remote_layout(TEST_KEY_A);

    EXPECT_TRUE(layout.history_prefix.ends_with('/'));
    EXPECT_TRUE(layout.commits_prefix.starts_with(layout.history_prefix));
    EXPECT_TRUE(layout.commits_prefix.ends_with('/'));
    EXPECT_TRUE(layout.heads_prefix.starts_with(layout.history_prefix));
    EXPECT_TRUE(layout.heads_prefix.ends_with('/'));
    EXPECT_TRUE(layout.epochs_prefix.starts_with(layout.history_prefix));
    EXPECT_TRUE(layout.epochs_prefix.ends_with('/'));
    EXPECT_TRUE(layout.gc_prefix.starts_with(layout.history_prefix));
    EXPECT_TRUE(layout.gc_prefix.ends_with('/'));
    EXPECT_TRUE(layout.barrier_identifier.starts_with(layout.gc_prefix));
    EXPECT_FALSE(layout.barrier_identifier.ends_with('/'));
    EXPECT_TRUE(layout.writers_prefix.starts_with(layout.gc_prefix));
    EXPECT_TRUE(layout.writers_prefix.ends_with('/'));
    EXPECT_TRUE(layout.probes_prefix.starts_with(layout.gc_prefix));
    EXPECT_TRUE(layout.probes_prefix.ends_with('/'));
    EXPECT_TRUE(layout.quarantine_prefix.starts_with(layout.gc_prefix));
    EXPECT_TRUE(layout.quarantine_prefix.ends_with('/'));
    EXPECT_TRUE(
        layout.quarantine_content_prefix.starts_with(layout.quarantine_prefix));
    EXPECT_TRUE(
        layout.quarantine_commits_prefix.starts_with(layout.quarantine_prefix));
}

TEST(RemoteLayoutTest, MarkerObjectRoundTrip) {
    const auto layout = derive_remote_layout(TEST_KEY_A);
    const HeadReference ref{
        .commit_id =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .ciphertext_id =
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"};

    const auto obj = marker_object(layout, ref);
    EXPECT_TRUE(obj.starts_with(layout.heads_prefix));
    EXPECT_TRUE(obj.ends_with(".head"));

    const auto parsed = parse_marker_object(layout, obj);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->commit_id, ref.commit_id);
    EXPECT_EQ(parsed->ciphertext_id, ref.ciphertext_id);

    // Rejection tests
    EXPECT_FALSE(parse_marker_object(layout, "invalid-marker").has_value());
    EXPECT_FALSE(parse_marker_object(layout, obj + ".extra").has_value());
    const auto layout_b = derive_remote_layout(TEST_KEY_B);
    EXPECT_FALSE(parse_marker_object(layout_b, obj).has_value());
}

TEST(RemoteLayoutTest, CommitObjectRoundTrip) {
    const auto layout = derive_remote_layout(TEST_KEY_A);
    const HeadReference ref{
        .commit_id =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .ciphertext_id =
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"};

    const auto obj = commit_object(layout, ref);
    EXPECT_TRUE(obj.starts_with(layout.commits_prefix));
    EXPECT_TRUE(obj.ends_with(".kcom"));

    const auto parsed = parse_commit_object(layout, obj);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->commit_id, ref.commit_id);
    EXPECT_EQ(parsed->ciphertext_id, ref.ciphertext_id);

    EXPECT_FALSE(parse_commit_object(layout, "invalid").has_value());
    const auto layout_b = derive_remote_layout(TEST_KEY_B);
    EXPECT_FALSE(parse_commit_object(layout_b, obj).has_value());
}

TEST(RemoteLayoutTest, EpochObjectRoundTrip) {
    const auto layout = derive_remote_layout(TEST_KEY_A);
    const std::string epoch_id =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::uint64_t seq = 42;

    const auto obj = epoch_object(layout, seq, epoch_id);
    EXPECT_TRUE(obj.starts_with(layout.epochs_prefix));
    EXPECT_TRUE(obj.ends_with(".epoch"));

    const auto parsed = parse_epoch_object(layout, obj);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->sequence, seq);
    EXPECT_EQ(parsed->epoch_id, epoch_id);

    EXPECT_FALSE(parse_epoch_object(layout, "invalid").has_value());
    const auto layout_b = derive_remote_layout(TEST_KEY_B);
    EXPECT_FALSE(parse_epoch_object(layout_b, obj).has_value());
}

TEST(RemoteLayoutTest, ControlAndHistoryClassification) {
    const auto layout = derive_remote_layout(TEST_KEY_A);

    EXPECT_TRUE(is_history_object(layout, layout.barrier_identifier));
    EXPECT_TRUE(is_control_object(layout, layout.barrier_identifier));

    const HeadReference ref{
        .commit_id =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .ciphertext_id =
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"};
    const auto commit = commit_object(layout, ref);
    EXPECT_TRUE(is_history_object(layout, commit));
    EXPECT_FALSE(is_control_object(layout, commit));

    const auto marker = marker_object(layout, ref);
    EXPECT_TRUE(is_history_object(layout, marker));
    EXPECT_FALSE(is_control_object(layout, marker));

    const std::string content_id =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    EXPECT_FALSE(is_history_object(layout, content_id));
    EXPECT_FALSE(is_control_object(layout, content_id));
}

TEST(RemoteLayoutTest, QuarantineRoundTrip) {
    const auto layout = derive_remote_layout(TEST_KEY_A);
    const std::string content_id =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    const auto q_content = quarantine_identifier(layout, content_id);
    ASSERT_TRUE(q_content.has_value());
    EXPECT_TRUE(q_content->starts_with(layout.quarantine_content_prefix));
    const auto restored_content = restore_destination(layout, *q_content);
    ASSERT_TRUE(restored_content.has_value());
    EXPECT_EQ(*restored_content, content_id);

    const HeadReference ref{
        .commit_id =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .ciphertext_id =
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"};
    const auto commit = commit_object(layout, ref);
    const auto q_commit = quarantine_identifier(layout, commit);
    ASSERT_TRUE(q_commit.has_value());
    EXPECT_TRUE(q_commit->starts_with(layout.quarantine_commits_prefix));
    const auto restored_commit = restore_destination(layout, *q_commit);
    ASSERT_TRUE(restored_commit.has_value());
    EXPECT_EQ(*restored_commit, commit);
}

} // namespace
} // namespace kasumi::application::history_storage
