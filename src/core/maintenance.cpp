#include "core/maintenance.hpp"

#include "core/hasher.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <map>
#include <ranges>
#include <string_view>
#include <utility>
#include <vector>

namespace kasumi::maintenance {

namespace {

std::string path_text(const std::filesystem::path& path) {
    return platform::path::to_logical_utf8(path);
}

} // namespace

AnalyzeResult analyze(const Snapshot& history_tree,
                      const Snapshot& local_tree,
                      std::span<const std::string> physical_identifiers) {
    if (!kasumi::valid_snapshot(history_tree, false)) {
        return std::unexpected(Error{
            .code = ErrorCode::InvalidHistoryTree,
            .detail = "invalid history tree",
            .paths = {},
        });
    }
    if (!kasumi::valid_snapshot(local_tree, true)) {
        return std::unexpected(Error{
            .code = ErrorCode::InvalidLocalTree,
            .detail = "invalid local tree",
            .paths = {},
        });
    }

    std::map<std::string, ObjectReference> references;
    for (const auto& row : history_tree.rows) {
        if (row.is_directory) {
            continue;
        }

        const auto identifier = hash_hex(row.hash);
        auto [position, inserted] =
            references.try_emplace(identifier,
                                   ObjectReference{
                                       .identifier = identifier,
                                       .size = row.size,
                                       .referenced_paths = {},
                                       .local_source = std::nullopt,
                                   });
        auto& reference = position->second;
        if (!inserted && reference.size != row.size) {
            auto paths = reference.referenced_paths;
            paths.push_back(platform::path::from_utf8(row.path));
            return std::unexpected(Error{
                .code = ErrorCode::ConflictingReference,
                .detail = "the same object has conflicting sizes",
                .paths = std::move(paths),
            });
        }
        reference.referenced_paths.push_back(
            platform::path::from_utf8(row.path));
    }

    using SourceKey = std::pair<std::string, std::uint64_t>;
    std::map<SourceKey, std::string_view> local_sources;
    for (const auto& row : local_tree.rows) {
        if (row.is_directory) {
            continue;
        }
        const SourceKey key{hash_hex(row.hash), row.size};
        auto position = local_sources.find(key);
        if (position == local_sources.end() || row.path < position->second) {
            local_sources.insert_or_assign(key, row.path);
        }
    }

    std::vector<std::string> physical{physical_identifiers.begin(),
                                      physical_identifiers.end()};
    std::ranges::sort(physical);
    physical.erase(std::ranges::unique(physical).begin(), physical.end());

    Inventory inventory;
    for (const auto& identifier : physical) {
        auto decoded = hash_from_hex(identifier);
        if (!decoded || hash_hex(*decoded) != identifier) {
            inventory.unknown_identifiers.push_back(identifier);
            continue;
        }
        auto reference = references.find(identifier);
        if (reference == references.end()) {
            inventory.orphan_identifiers.push_back(identifier);
            continue;
        }
        reference->second.physically_present = true;
    }

    for (auto& [identifier, reference] : references) {
        std::ranges::sort(reference.referenced_paths, {}, path_text);
        if (auto source = local_sources.find({identifier, reference.size});
            source != local_sources.end()) {
            reference.local_source = platform::path::from_utf8(source->second);
        }
        inventory.referenced_objects.push_back(std::move(reference));
    }

    return inventory;
}

} // namespace kasumi::maintenance
