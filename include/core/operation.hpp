#ifndef KASUMI_OPERATION_HPP
#define KASUMI_OPERATION_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace kasumi {

// Possible actions in a synchronization plan.
enum class Action : std::uint8_t {
    // Moves path to alt_path in the local directory.
    RenameLocal = 0,
    // Uploads local content referenced by path.
    Upload = 1,
    // Creates a local directory.
    CreateLocalDirectory = 2,
    // Adds a directory to the logical remote tree.
    CreateRemoteDirectory = 3,
    // Downloads remote content for hash to local.
    Download = 4,
    // Removes a local file.
    DeleteLocal = 5,
    // Removes an empty local directory.
    DeleteLocalDirectory = 6,
    // Removes a file from the logical remote tree.
    DeleteRemote = 7,
    // Removes a directory from the logical remote tree.
    DeleteRemoteDirectory = 8,
    // Sentinel used to dimension the phases.
    Count = 9
};

// Number of executable values in Action.
inline constexpr std::size_t ActionCount =
    static_cast<std::size_t>(Action::Count);

// Converts an action to a table index.
inline constexpr std::size_t action_index(Action action) noexcept {
    return static_cast<std::size_t>(action);
}

// Indicates whether action represents an executable action.
inline constexpr bool is_valid_action(Action action) noexcept {
    return action_index(action) < ActionCount;
}

// Indicates whether the action mutates the local file system.
inline constexpr bool is_local_mutation(Action action) noexcept {
    constexpr std::array local{
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        false,
        false,
    };

    return is_valid_action(action) && local[action_index(action)];
}

// Indicates whether the action only mutates the logical remote tree.
inline constexpr bool is_logical_mutation(Action action) noexcept {
    return action == Action::CreateRemoteDirectory ||
           action == Action::DeleteRemote ||
           action == Action::DeleteRemoteDirectory;
}

// Elementary operation of a synchronization plan.
struct Operation {
    Action action = Action::Count;
    // Primary relative path of the action.
    std::filesystem::path path;
    // BLAKE3 hash used in file transfers.
    std::string hash;
    // Destination of RenameLocal.
    std::filesystem::path alt_path;
    // Logical file size in bytes.
    std::uint64_t size = 0;
    // Requests an exclusive destination to preserve conflicts.
    bool exclusive_destination = false;
};

// Operations grouped by Action; offsets demarcate each phase.
struct SyncPlan {
    // Operations ordered by phase.
    std::vector<Operation> operations;
    // Phase boundaries indexed by Action and terminated by Count.
    std::array<std::uint32_t, ActionCount + 1> offsets{};
    // Generation the plan must produce or preserve.
    std::uint64_t target_generation = 0;
};

// Validates that operation relative paths do not escape the root.
bool has_safe_paths(const Operation& operation);

// Creates and orders a plan for the target generation.
SyncPlan make_sync_plan(std::vector<Operation> operations,
                        std::uint64_t target_generation);

// Groups operations by Action and rebuilds offsets.
void order_sync_plan(SyncPlan& plan);

// Rebuilds offsets for operations already grouped by Action.
void rebuild_sync_plan_offsets(SyncPlan& plan) noexcept;

// Returns mutable phase span corresponding to the action.
std::span<Operation> sync_plan_phase(SyncPlan& plan, Action action) noexcept;

// Returns phase span corresponding to the action.
std::span<const Operation> sync_plan_phase(const SyncPlan& plan,
                                           Action action) noexcept;

// Returns all plan operations in phase order.
std::span<const Operation> sync_plan_operations(const SyncPlan& plan) noexcept;

// Validates bounds, offsets, and action grouping.
bool valid_sync_plan(const SyncPlan& plan) noexcept;

// Returns total number of operations in the plan.
std::size_t sync_plan_size(const SyncPlan& plan) noexcept;

// Indicates whether the plan contains no operations.
bool sync_plan_empty(const SyncPlan& plan) noexcept;

} // namespace kasumi

#endif
