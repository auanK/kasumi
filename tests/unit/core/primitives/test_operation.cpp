#include "core/operation.hpp"
#include "platform/path.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace {

using kasumi::Action;
using kasumi::Operation;
using kasumi::SyncPlan;

constexpr std::array<Action, kasumi::ActionCount> all_actions{
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

Operation make_operation(Action action, std::string_view relative_path) {
    return {
        .action = action,
        .path = kasumi::platform::path::from_utf8(relative_path),
        .hash = {},
        .alt_path = {},
        .size = 0,
        .exclusive_destination = false,
    };
}

std::vector<std::string> phase_paths(const SyncPlan& plan, Action action) {
    std::vector<std::string> paths;
    for (const auto& operation : kasumi::sync_plan_phase(plan, action)) {
        paths.push_back(
            kasumi::platform::path::to_logical_utf8(operation.path));
    }
    return paths;
}

SyncPlan make_populated_plan() {
    std::vector<Operation> operations;
    for (auto it = all_actions.rbegin(); it != all_actions.rend(); ++it) {
        operations.push_back(make_operation(
            *it, "operation-" + std::to_string(kasumi::action_index(*it))));
    }
    return kasumi::make_sync_plan(std::move(operations), 44);
}

TEST(ActionTest, ClassifiesEveryDefinedAction) {
    constexpr std::array<bool, kasumi::ActionCount> expected_local_mutation{
        true, false, true, false, true, true, true, false, false};
    constexpr std::array<bool, kasumi::ActionCount> expected_logical_mutation{
        false, false, false, true, false, false, false, true, true};

    EXPECT_EQ(kasumi::ActionCount, all_actions.size());
    for (std::size_t index = 0; index < all_actions.size(); ++index) {
        EXPECT_EQ(kasumi::action_index(all_actions[index]), index);
        EXPECT_TRUE(kasumi::is_valid_action(all_actions[index]));
        EXPECT_EQ(kasumi::is_local_mutation(all_actions[index]),
                  expected_local_mutation[index]);
        EXPECT_EQ(kasumi::is_logical_mutation(all_actions[index]),
                  expected_logical_mutation[index]);
    }
    EXPECT_FALSE(kasumi::is_valid_action(Action::Count));
    EXPECT_FALSE(kasumi::is_local_mutation(Action::Count));
    EXPECT_FALSE(kasumi::is_logical_mutation(Action::Count));
}

TEST(SyncPlanTest, StablyOrdersOperationsAndPreservesFields) {
    Operation first_upload = make_operation(Action::Upload, "upload-first");
    first_upload.hash = "first-hash";
    first_upload.size = 17;

    Operation rename = make_operation(Action::RenameLocal, "before.txt");
    rename.alt_path = kasumi::platform::path::from_utf8("after.txt");
    rename.hash = "rename-hash";
    rename.size = 29;
    rename.exclusive_destination = true;

    const SyncPlan plan = kasumi::make_sync_plan(
        {make_operation(Action::DeleteRemote, "remote-old"),
         first_upload,
         make_operation(Action::Download, "download-first"),
         rename,
         make_operation(Action::CreateLocalDirectory, "local-dir"),
         make_operation(Action::Upload, "upload-second"),
         make_operation(Action::Download, "download-second")},
        91);

    EXPECT_TRUE(kasumi::valid_sync_plan(plan));
    EXPECT_EQ(plan.target_generation, std::uint64_t{91});
    EXPECT_EQ(phase_paths(plan, Action::Upload),
              (std::vector<std::string>{"upload-first", "upload-second"}));
    EXPECT_EQ(phase_paths(plan, Action::Download),
              (std::vector<std::string>{"download-first", "download-second"}));

    const auto rename_phase =
        kasumi::sync_plan_phase(plan, Action::RenameLocal);
    ASSERT_EQ(rename_phase.size(), 1U);
    EXPECT_EQ(rename_phase.front().path,
              kasumi::platform::path::from_utf8("before.txt"));
    EXPECT_EQ(rename_phase.front().alt_path,
              kasumi::platform::path::from_utf8("after.txt"));
    EXPECT_EQ(rename_phase.front().hash, "rename-hash");
    EXPECT_EQ(rename_phase.front().size, std::uint64_t{29});
    EXPECT_TRUE(rename_phase.front().exclusive_destination);
}

TEST(SyncPlanTest, UsesCanonicalOffsetsAndExposesConstRanges) {
    const SyncPlan empty = kasumi::make_sync_plan({}, 0);
    EXPECT_TRUE(kasumi::valid_sync_plan(empty));
    EXPECT_TRUE(kasumi::sync_plan_empty(empty));
    EXPECT_EQ(kasumi::sync_plan_size(empty), 0U);
    EXPECT_TRUE(kasumi::sync_plan_operations(empty).empty());
    for (const Action action : all_actions)
        EXPECT_TRUE(kasumi::sync_plan_phase(empty, action).empty());

    const SyncPlan plan =
        kasumi::make_sync_plan({make_operation(Action::Download, "download"),
                                make_operation(Action::Upload, "upload")},
                               3);
    EXPECT_TRUE(kasumi::valid_sync_plan(plan));
    EXPECT_EQ(plan.offsets,
              (std::array<std::uint32_t, kasumi::ActionCount + 1>{
                  0, 0, 1, 1, 1, 2, 2, 2, 2, 2}));

    auto rebuilt = plan;
    rebuilt.offsets.fill(0);
    EXPECT_FALSE(kasumi::valid_sync_plan(rebuilt));
    kasumi::rebuild_sync_plan_offsets(rebuilt);
    EXPECT_TRUE(kasumi::valid_sync_plan(rebuilt));
    EXPECT_EQ(rebuilt.offsets, plan.offsets);
}

TEST(SyncPlanTest, RejectsInvalidActions) {
    EXPECT_THROW(
        kasumi::make_sync_plan({make_operation(Action::Count, "invalid")}, 0),
        std::invalid_argument);

    SyncPlan invalid;
    invalid.operations.push_back(make_operation(Action::Upload, "valid"));
    invalid.operations.push_back(make_operation(Action::Count, "invalid"));
    EXPECT_THROW(kasumi::order_sync_plan(invalid), std::invalid_argument);
}

TEST(SyncPlanTest, PlacesEveryActionInItsCanonicalPhase) {
    const SyncPlan plan = make_populated_plan();
    ASSERT_TRUE(kasumi::valid_sync_plan(plan));
    EXPECT_EQ(kasumi::sync_plan_size(plan), kasumi::ActionCount);
    for (const auto action : all_actions) {
        const auto phase = kasumi::sync_plan_phase(plan, action);
        ASSERT_EQ(phase.size(), 1U);
        EXPECT_EQ(phase.front().action, action);
        EXPECT_EQ(plan.offsets[kasumi::action_index(action)],
                  kasumi::action_index(action));
    }
    EXPECT_EQ(plan.offsets.back(), kasumi::sync_plan_size(plan));
    EXPECT_TRUE(kasumi::sync_plan_phase(plan, Action::Count).empty());
}

TEST(SyncPlanTest, MutableAndConstPhasesExposeOnlyCanonicalRanges) {
    SyncPlan plan = make_populated_plan();
    static_assert(
        std::is_same_v<decltype(kasumi::sync_plan_phase(plan, Action::Upload)),
                       std::span<Operation>>);

    std::size_t visited = 0;
    for (const auto action : all_actions) {
        for (auto& operation : kasumi::sync_plan_phase(plan, action)) {
            EXPECT_EQ(operation.action, action);
            ++visited;
        }
    }
    EXPECT_EQ(visited, kasumi::sync_plan_size(plan));
    kasumi::sync_plan_phase(plan, Action::Upload).front().path =
        kasumi::platform::path::from_utf8("changed");

    const SyncPlan& constant = plan;
    static_assert(std::is_same_v<decltype(kasumi::sync_plan_phase(
                                     constant, Action::Upload)),
                                 std::span<const Operation>>);
    EXPECT_EQ(kasumi::sync_plan_phase(constant, Action::Upload).front().path,
              kasumi::platform::path::from_utf8("changed"));
    EXPECT_TRUE(kasumi::sync_plan_phase(plan, Action::Count).empty());
    EXPECT_TRUE(kasumi::sync_plan_phase(constant, Action::Count).empty());
}

TEST(SyncPlanTest, DetectsCorruptedOffsetsActionsAndFinalSize) {
    const SyncPlan canonical = make_populated_plan();
    ASSERT_TRUE(kasumi::valid_sync_plan(canonical));

    auto wrong_start = canonical;
    wrong_start.offsets.front() = 1;
    EXPECT_FALSE(kasumi::valid_sync_plan(wrong_start));

    auto decreasing = canonical;
    decreasing.offsets[2] = 0;
    EXPECT_FALSE(kasumi::valid_sync_plan(decreasing));

    auto wrong_end = canonical;
    --wrong_end.offsets.back();
    EXPECT_FALSE(kasumi::valid_sync_plan(wrong_end));

    auto wrong_action = canonical;
    const auto upload_offset =
        wrong_action.offsets[kasumi::action_index(Action::Upload)];
    wrong_action.operations[upload_offset].action = Action::Download;
    EXPECT_FALSE(kasumi::valid_sync_plan(wrong_action));

    auto invalid_action = canonical;
    invalid_action.operations.back().action = Action::Count;
    EXPECT_FALSE(kasumi::valid_sync_plan(invalid_action));
}

TEST(OperationPathTest, AcceptsNormalRelativePathsAndLiteralDotsAndColons) {
    Operation operation =
        make_operation(Action::RenameLocal, "archive/report..draft.txt");
    operation.alt_path =
        kasumi::platform::path::from_utf8("archive/name:revision...txt");
    EXPECT_TRUE(kasumi::has_safe_paths(operation));

    operation.path = std::filesystem::path{"folder"} / "..." / "entry.txt";
    operation.alt_path = kasumi::platform::path::from_utf8("renamed:copy.txt");
    EXPECT_TRUE(kasumi::has_safe_paths(operation));
}

TEST(OperationPathTest, RejectsAbsolutePathsAndTraversal) {
#if defined(_WIN32)
    const std::filesystem::path absolute_path{"C:/outside/file.txt"};
#else
    const std::filesystem::path absolute_path{"/outside/file.txt"};
#endif
    Operation operation = make_operation(Action::Upload, "inside/file.txt");
    operation.path = absolute_path;
    EXPECT_FALSE(kasumi::has_safe_paths(operation));

    operation.path = kasumi::platform::path::from_utf8("inside/file.txt");
    operation.alt_path = absolute_path;
    EXPECT_FALSE(kasumi::has_safe_paths(operation));

    operation.path = std::filesystem::path{"inside"} / ".." / "outside.txt";
    EXPECT_FALSE(kasumi::has_safe_paths(operation));
}

} // namespace
