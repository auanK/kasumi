#include "application/history_storage/epoch.hpp"
#include "core/history.hpp"

#include <gtest/gtest.h>

#include <cstdint>
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
    return LoadedCommit{
        .id = make_id(id_char),
        .commit = Commit{.height = height,
                         .created_at = created_at,
                         .parents = std::move(parents)}};
}

TEST(EpochPlannerTest, RespectsDepthAndAgeLimits) {
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 100),
        make_loaded('b', 1, 200, {make_id('a')}),
        make_loaded('c', 2, 3700, {make_id('b')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 2, .min_history_age_hours = 1});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->prunable_commits, std::vector<std::string>{make_id('a')});
    ASSERT_EQ(result->anchors.size(), 1U);
    EXPECT_EQ(result->anchors.front().commit_id, make_id('a'));
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

TEST(EpochPlannerTest, MultipleHeadsUseNewestAuthenticatedTimestamp) {
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 100),
        make_loaded('b', 1, 3000, {make_id('a')}),
        make_loaded('c', 1, 3700, {make_id('a')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 1, .min_history_age_hours = 1});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->prunable_commits, std::vector<std::string>{make_id('a')});
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
        make_loaded('a', 0, 100),
        make_loaded('b', 1, 200, {make_id('a')}),
        make_loaded('c', 2, 3700, {make_id('b')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 2, .min_history_age_hours = 1});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->prunable_commits.front(), make_id('a'));
}

TEST(EpochPlannerTest, OneSecondBelowAgeBoundaryDoesNotQualify) {
    const std::vector<LoadedCommit> commits{
        make_loaded('a', 0, 100),
        make_loaded('b', 1, 200, {make_id('a')}),
        make_loaded('c', 2, 3699, {make_id('b')})};

    const auto result = plan_pruning(
        commits, {.min_history_depth = 2, .min_history_age_hours = 1});
    ASSERT_FALSE(result.has_value());
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

TEST(EpochPlannerTest, LegacyZeroTimestampIsNotAncient) {
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
