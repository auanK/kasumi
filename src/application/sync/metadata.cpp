#include "application/sync/metadata.hpp"

#include "platform/path.hpp"

#include <algorithm>
#include <ranges>
#include <string_view>
#include <unordered_set>

namespace kasumi::application::sync {
namespace {

void add_path_and_ancestors(std::unordered_set<std::string>& paths,
                            std::string_view path,
                            bool include_target) {
    if (include_target) {
        paths.emplace(path);
    }
    while (!path.empty()) {
        path = row_parent(path);
        paths.emplace(path);
    }
}

} // namespace

std::expected<std::vector<std::string>, std::string>
metadata_restore_paths(const transaction::Record& record,
                       const Snapshot& expected_tree,
                       const Snapshot* observed_tree) {
    if (record.progress.size() != record.plan.operations.size()) {
        return std::unexpected("transaction progress does not match its plan");
    }

    std::unordered_set<std::string> paths;
    for (std::size_t index = 0; index < record.plan.operations.size();
         ++index) {
        if (record.progress[index].state !=
            transaction::OperationState::Applied) {
            continue;
        }
        const auto& operation = record.plan.operations[index];
        const auto path = platform::path::to_logical_utf8(operation.path);
        switch (operation.action) {
            case Action::Download:
            case Action::CreateLocalDirectory:
                add_path_and_ancestors(paths, path, true);
                break;
            case Action::DeleteLocal:
            case Action::DeleteLocalDirectory:
                add_path_and_ancestors(paths, row_parent(path), true);
                break;
            case Action::RenameLocal:
                add_path_and_ancestors(paths, path, true);
                add_path_and_ancestors(
                    paths, platform::path::to_logical_utf8(operation.alt_path), true);
                break;
            case Action::Upload:
            case Action::CreateRemoteDirectory:
            case Action::DeleteRemote:
            case Action::DeleteRemoteDirectory:
            case Action::Count:
                break;
        }
    }

    if (!record.publication_required && observed_tree != nullptr) {
        for (const auto& expected : expected_tree.rows) {
            if (!expected.is_directory) {
                continue;
            }
            const auto* observed = find_row(*observed_tree, expected.path);
            if (observed != nullptr && observed->is_directory &&
                observed->mtime != expected.mtime) {
                paths.emplace(expected.path);
            }
        }
    }

    std::vector<std::string> result;
    result.reserve(paths.size());
    for (const auto& path : paths) {
        if (find_row(expected_tree, path) != nullptr) {
            result.push_back(path);
        }
    }
    std::ranges::sort(
        result, [&expected_tree](const auto& left, const auto& right) {
            const auto* left_row = find_row(expected_tree, left);
            const auto* right_row = find_row(expected_tree, right);
            if (left_row->is_directory != right_row->is_directory) {
                return !left_row->is_directory;
            }
            if (left_row->is_directory) {
                const auto left_depth =
                    static_cast<std::size_t>(std::ranges::count(left, '/'));
                const auto right_depth =
                    static_cast<std::size_t>(std::ranges::count(right, '/'));
                if (left_depth != right_depth) {
                    return left_depth > right_depth;
                }
                if (left.empty() != right.empty()) {
                    return !left.empty();
                }
            }
            return path_less(left, right);
        });
    return result;
}

} // namespace kasumi::application::sync
