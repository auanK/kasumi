#include "core/operation.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace kasumi {

bool has_safe_paths(const Operation& operation) {
    const auto unsafe = [](const std::filesystem::path& path) {
        return path.is_absolute() || path.has_root_name() ||
               path.has_root_directory() ||
               std::ranges::find(path, std::filesystem::path{".."}) !=
                   path.end();
    };

    return !unsafe(operation.path) && !unsafe(operation.alt_path);
}

SyncPlan make_sync_plan(std::vector<Operation> operations,
                        std::uint64_t target_generation) {
    SyncPlan plan{
        .operations = std::move(operations),
        .offsets = {},
        .target_generation = target_generation,
    };

    order_sync_plan(plan);

    return plan;
}

void order_sync_plan(SyncPlan& plan) {
    if (plan.operations.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("sync plan exceeds 32-bit "
                                "operation index");
    }

    if (!std::ranges::all_of(
            plan.operations, is_valid_action, &Operation::action)) {
        throw std::invalid_argument("sync plan contains an invalid action");
    }

    std::ranges::stable_sort(
        plan.operations, {}, [](const Operation& operation) {
            return action_index(operation.action);
        });

    rebuild_sync_plan_offsets(plan);
}

void rebuild_sync_plan_offsets(SyncPlan& plan) noexcept {
    std::size_t position = 0;

    for (std::size_t action = 0; action < ActionCount; ++action) {
        plan.offsets[action] = static_cast<std::uint32_t>(position);

        while (position < plan.operations.size() &&
               action_index(plan.operations[position].action) == action) {
            ++position;
        }
    }

    plan.offsets[ActionCount] = static_cast<std::uint32_t>(position);
}

std::span<Operation> sync_plan_phase(SyncPlan& plan, Action action) noexcept {
    const auto index = action_index(action);

    if (index >= ActionCount) {
        return {};
    }

    return std::span{plan.operations}.subspan(
        plan.offsets[index], plan.offsets[index + 1] - plan.offsets[index]);
}

std::span<const Operation> sync_plan_phase(const SyncPlan& plan,
                                           Action action) noexcept {
    const auto index = action_index(action);

    if (index >= ActionCount) {
        return {};
    }

    return std::span{plan.operations}.subspan(
        plan.offsets[index], plan.offsets[index + 1] - plan.offsets[index]);
}

std::span<const Operation> sync_plan_operations(const SyncPlan& plan) noexcept {
    return plan.operations;
}

bool valid_sync_plan(const SyncPlan& plan) noexcept {
    if (plan.operations.size() > std::numeric_limits<std::uint32_t>::max() ||
        plan.offsets.front() != 0 ||
        plan.offsets.back() != plan.operations.size()) {
        return false;
    }

    for (std::size_t action = 0; action < ActionCount; ++action) {
        if (plan.offsets[action] > plan.offsets[action + 1]) {
            return false;
        }

        for (auto index = plan.offsets[action];
             index < plan.offsets[action + 1];
             ++index) {
            if (action_index(plan.operations[index].action) != action) {
                return false;
            }
        }
    }

    return true;
}

std::size_t sync_plan_size(const SyncPlan& plan) noexcept {
    return plan.operations.size();
}

bool sync_plan_empty(const SyncPlan& plan) noexcept {
    return plan.operations.empty();
}

} // namespace kasumi