#include "application/history_storage/epoch.hpp"
#include "core/history.hpp"

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace kasumi::application::history_storage::epoch;
using kasumi::history::Commit;
using kasumi::history::LoadedCommit;

std::string make_id(char digit) {
    return std::string(64, digit);
}

LoadedCommit make_loaded(char id_char,
                         std::uint64_t height,
                         std::int64_t created_at,
                         std::vector<std::string> parents = {}) {
    return LoadedCommit{.id = make_id(id_char),
                        .commit = Commit{.height = height,
                                         .created_at = created_at,
                                         .parents = std::move(parents)}};
}

TEST(EpochPlannerTest, RespectsDepthAndAgeLimits) {
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 100),
        make_loaded('b', 1, 100, {make_id('a')}),
        make_loaded('c', 2, 3700, {make_id('b')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 2, .min_history_age_hours = 1});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->prunable_commits, std::vector<std::string>{make_id('a')});
    ASSERT_EQ(result->anchors.size(), 1U);
    EXPECT_EQ(result->anchors.front().commit_id, make_id('b'));
    EXPECT_EQ(result->anchors.front().height, 1U);
}

TEST(EpochPlannerTest, BothLimitsMustBeReached) {
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 100),
        make_loaded('b', 1, 200, {make_id('a')}),
        make_loaded('c', 2, 300, {make_id('b')})};

    const auto age_not_reached = plan_pruning(
        commits, {.min_history_depth = 2, .min_history_age_hours = 1});
    ASSERT_FALSE(age_not_reached.has_value());

    const auto depth_not_reached = plan_pruning(
        std::vector<LoadedCommit>{make_loaded('a', 0, 100),
                                  make_loaded('b', 1, 3700, {make_id('a')})},
        {.min_history_depth = 2, .min_history_age_hours = 1});
    ASSERT_FALSE(depth_not_reached.has_value());
}

TEST(EpochPlannerTest,
     MultiHeadProtectsMergeBaseAndUsesNewestHeadTimestampForOlderAncestors) {
    const std::vector<LoadedCommit> commits{
        make_loaded('r', 0, 50),
        make_loaded('a', 1, 100, {make_id('r')}),
        make_loaded('b', 2, 3000, {make_id('a')}),
        make_loaded('c', 2, 3700, {make_id('a')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 1, .min_history_age_hours = 1});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->prunable_commits, std::vector<std::string>{make_id('r')});
    ASSERT_EQ(result->anchors.size(), 1U);
    EXPECT_EQ(result->anchors.front().commit_id, make_id('a'));
}

TEST(EpochPlannerTest, WallClockPassageAloneDoesNotPrune) {
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 100),
        make_loaded('b', 1, 200, {make_id('a')}),
        make_loaded('c', 2, 300, {make_id('b')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 2, .min_history_age_hours = 1});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().reason, "no commits reached retention limits");
}

TEST(EpochPlannerTest, ExactAgeBoundaryQualifies) {
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 50),
        make_loaded('b', 1, 100, {make_id('a')}),
        make_loaded('c', 2, 3700, {make_id('b')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 2, .min_history_age_hours = 1});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->prunable_commits.front(), make_id('a'));
}

TEST(EpochPlannerTest, OneSecondBelowAgeBoundaryDoesNotQualify) {
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 50),
        make_loaded('b', 1, 100, {make_id('a')}),
        make_loaded('c', 2, 3699, {make_id('b')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 2, .min_history_age_hours = 1});
    ASSERT_FALSE(result.has_value());
}

TEST(EpochPlannerTest, OldCommitSupersededMinutesAgoIsProtected) {
    // Commit 'a' existed for years, was replaced at t=3500, followed by 5
    // newer commits up to t=3800. Age must be counted from replacement (3500).
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 100),
        make_loaded('b', 1, 3500, {make_id('a')}),
        make_loaded('c', 2, 3600, {make_id('b')}),
        make_loaded('d', 3, 3650, {make_id('c')}),
        make_loaded('e', 4, 3700, {make_id('d')}),
        make_loaded('f', 5, 3750, {make_id('e')}),
        make_loaded('g', 6, 3800, {make_id('f')})};

    const auto too_recent = plan_pruning(
        commits, {.min_history_depth = 5, .min_history_age_hours = 1});
    EXPECT_FALSE(too_recent.has_value());

    const auto after_window = plan_pruning(
        commits,
        {.min_history_depth = 5, .min_history_age_hours = 1},
        {.reference_now_unix = 3500 + 3600});
    ASSERT_TRUE(after_window.has_value());
    EXPECT_EQ(after_window->prunable_commits,
              std::vector<std::string>{make_id('a')});
    ASSERT_EQ(after_window->anchors.size(), 1U);
    EXPECT_EQ(after_window->anchors.front().commit_id, make_id('b'));
}

TEST(EpochPlannerTest, DefaultFiveGenerationsAndSixHoursRetention) {
    const std::int64_t t0 = 1'700'000'000;
    const std::vector<LoadedCommit> rapid_eight{
        make_loaded('a', 0, t0),
        make_loaded('b', 1, t0 + 10, {make_id('a')}),
        make_loaded('c', 2, t0 + 20, {make_id('b')}),
        make_loaded('d', 3, t0 + 30, {make_id('c')}),
        make_loaded('e', 4, t0 + 40, {make_id('d')}),
        make_loaded('f', 5, t0 + 50, {make_id('e')}),
        make_loaded('g', 6, t0 + 60, {make_id('f')}),
        make_loaded('h', 7, t0 + 70, {make_id('g')})};

    // >5 versions within 6h -> nothing expires.
    EXPECT_FALSE(plan_pruning(rapid_eight, {}).has_value());

    // <5 generations even after 24h -> nothing expires.
    const std::vector<LoadedCommit> four_old{
        make_loaded('a', 0, t0),
        make_loaded('b', 1, t0 + 10, {make_id('a')}),
        make_loaded('c', 2, t0 + 20, {make_id('b')}),
        make_loaded('d', 3, t0 + 30, {make_id('c')})};
    EXPECT_FALSE(plan_pruning(
                     four_old, {}, {.reference_now_unix = t0 + 24 * 3600})
                     .has_value());

    // 8 commits after 6h+ from reference clock: keeps depths 0..4 (d..h),
    // anchors at d (height 3), prunes a, b, c.
    const auto pruned = plan_pruning(
        rapid_eight, {}, {.reference_now_unix = t0 + 6 * 3600 + 100});
    ASSERT_TRUE(pruned.has_value());
    EXPECT_EQ(pruned->prunable_commits,
              (std::vector<std::string>{make_id('a'), make_id('b'), make_id('c')}));
    ASSERT_EQ(pruned->anchors.size(), 1U);
    EXPECT_EQ(pruned->anchors.front().commit_id, make_id('d'));
    EXPECT_EQ(pruned->anchors.front().height, 3U);
}

TEST(EpochPlannerTest,
     MixedParentMergeProtectsMarkedAncestralAndProtectedCommits) {
    const std::int64_t t0 = 1'700'000'000;
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, t0),
        make_loaded('b', 1, t0 + 10, {make_id('a')}),
        make_loaded('c', 2, t0 + 20, {make_id('b')}),
        make_loaded('x', 1, t0 + 30, {make_id('a')}),
        make_loaded('m', 3, t0 + 7 * 3600, {make_id('c'), make_id('x')}),
        make_loaded('n', 4, t0 + 7 * 3600 + 20, {make_id('m')})};

    // Depth from head 'n': m=1, x=2, c=2, b=3, a=3.
    // 'x' and 'c' were superseded by 'm' only 20s ago, while 'a' and 'b' were
    // superseded >6h ago at t0+30 and t0+20, so {a, b} expire and both 'c' and
    // 'x' become boundary anchors above the pruned history.
    const auto pruned =
        plan_pruning(commits, {.min_history_depth = 2, .min_history_age_hours = 6});
    ASSERT_TRUE(pruned.has_value());
    EXPECT_EQ(pruned->prunable_commits,
              (std::vector<std::string>{make_id('a'), make_id('b')}));
    EXPECT_EQ(pruned->anchors,
              (std::vector<Anchor>{
                  Anchor{.commit_id = make_id('c'), .height = 2U},
                  Anchor{.commit_id = make_id('x'), .height = 1U}}));

    // Protecting 'b' keeps 'b' and pushes that branch's anchor to 'b', pruning
    // only 'a' while keeping 'x' anchored above pruned 'a'.
    const std::vector<std::string> protected_ids{make_id('b')};
    const auto protected_plan = plan_pruning(
        commits,
        {.min_history_depth = 2, .min_history_age_hours = 6},
        {.protected_commit_ids = protected_ids});
    ASSERT_TRUE(protected_plan.has_value());
    EXPECT_EQ(protected_plan->prunable_commits,
              std::vector<std::string>{make_id('a')});
    EXPECT_EQ(protected_plan->anchors,
              (std::vector<Anchor>{
                  Anchor{.commit_id = make_id('b'), .height = 1U},
                  Anchor{.commit_id = make_id('x'), .height = 1U}}));

    // Marking 'b' as an ancestral HEAD keeps 'b' at depth 0 and 'a' at depth 1
    // (< min_history_depth = 2), so neither 'b' nor 'a' can be pruned.
    const std::vector<std::string> marked_b{make_id('b')};
    EXPECT_FALSE(plan_pruning(commits,
                              {.min_history_depth = 2, .min_history_age_hours = 6},
                              {.marked_commit_ids = marked_b})
                     .has_value());

    // Marking 'a' directly protects 'a' from pruning even though 'b' above it
    // expires under depth >= 2 and age >= 6h.
    const std::vector<std::string> marked_a{make_id('a')};
    const auto marked_a_plan =
        plan_pruning(commits,
                     {.min_history_depth = 2, .min_history_age_hours = 6},
                     {.marked_commit_ids = marked_a});
    ASSERT_TRUE(marked_a_plan.has_value());
    EXPECT_EQ(marked_a_plan->prunable_commits,
              std::vector<std::string>{make_id('b')});
}

TEST(EpochPlannerTest, DepthStillRequired) {
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 100), make_loaded('b', 1, 3700, {make_id('a')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 2, .min_history_age_hours = 1});
    ASSERT_FALSE(result.has_value());
}

TEST(EpochPlannerTest, AgeStillRequired) {
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 100), make_loaded('b', 1, 300, {make_id('a')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 1, .min_history_age_hours = 1});
    ASSERT_FALSE(result.has_value());
}

TEST(EpochPlannerTest, ZeroTimestampPreventsUnsafeAgePruning) {
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 0),
        make_loaded('b', 1, 100, {make_id('a')}),
        make_loaded('c', 2, 3700, {make_id('b')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 2, .min_history_age_hours = 1});
    ASSERT_FALSE(result.has_value());
}

TEST(EpochPlannerTest, AllZeroHistoryDoesNotPrune) {
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 0),
        make_loaded('b', 1, 0, {make_id('a')}),
        make_loaded('c', 2, 0, {make_id('b')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 1, .min_history_age_hours = 1});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().reason, "no authenticated commit timestamp");
}

TEST(EpochPlannerTest, RegressiveTimestampFailsConservatively) {
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 5000), make_loaded('b', 1, 4000, {make_id('a')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 1, .min_history_age_hours = 1});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().reason, "timestamp regression detected");
}

TEST(EpochPlannerTest, MissingParentIsAllowedAtEpochFrontier) {
    const std::vector<LoadedCommit> commits{
        make_loaded('b', 1, 3700, {make_id('a')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 1, .min_history_age_hours = 1});
    ASSERT_FALSE(result.has_value());
}

TEST(EpochPlannerTest, DefensiveLimit) {
    std::vector<LoadedCommit> commits;
    for (std::size_t i = 0;
         i < kasumi::history::maximum_loaded_commit_count + 1;
         ++i) {
        commits.push_back(make_loaded('a', 0, 100));
    }

    const auto result = plan_pruning(
        commits, {.min_history_depth = 0, .min_history_age_hours = 0});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().reason, "defensive limit exceeded");
}

} // namespace
