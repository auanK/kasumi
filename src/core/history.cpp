#include "core/history.hpp"

#include "core/wire.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstring>
#include <limits>
#include <map>
#include <new>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace kasumi::history {

namespace {

using Index = std::unordered_map<std::string, const LoadedCommit*>;
using PathSet = std::unordered_set<std::string>;

std::vector<std::byte> serialize_tree(const Snapshot& snapshot,
                                      std::uint64_t height) {
    wire::Writer writer;
    writer.buffer.reserve(12 + snapshot.rows.size() * 64);

    const char magic[] = "KASU";
    wire::write_bytes(writer, std::as_bytes(std::span{magic, 4}));
    wire::write<std::uint64_t>(writer, height);

    struct OpenDirectory {
        std::size_t row;
        std::size_t count_offset;
        std::uint32_t children;
    };
    std::vector<OpenDirectory> directories;

    const auto close = [&] {
        const auto directory = directories.back();
        auto children = directory.children;
        if constexpr (std::endian::native != std::endian::little) {
            children = std::byteswap(children);
        }
        std::memcpy(writer.buffer.data() + directory.count_offset,
                    &children,
                    sizeof(children));
        directories.pop_back();
    };

    for (std::size_t index = 0; index < snapshot.rows.size(); ++index) {
        const auto& row = snapshot.rows[index];
        while (!directories.empty() &&
               row_parent(row.path) !=
                   snapshot.rows[directories.back().row].path) {
            close();
        }
        if (!directories.empty()) {
            ++directories.back().children;
        }

        wire::write_string(writer, row_name(row.path));
        wire::write_array(writer, row.hash);
        wire::write<std::uint64_t>(writer, row.size);
        wire::write<std::int64_t>(writer, row.mtime);
        wire::write<std::uint8_t>(writer,
                                  static_cast<std::uint8_t>(row.is_directory));

        const auto count_offset = writer.buffer.size();
        wire::write<std::uint32_t>(writer, 0U);
        if (row.is_directory) {
            directories.push_back({index, count_offset, 0U});
        }
    }
    while (!directories.empty()) {
        close();
    }

    return writer.buffer;
}

std::expected<Snapshot, Error> deserialize_tree(std::span<const std::byte> data,
                                                std::uint64_t& height) {
    const auto fail = [](const char* message) {
        return std::unexpected(Error{ErrorCode::InvalidEncoding, message});
    };
    constexpr std::array magic{
        std::byte{'K'}, std::byte{'A'}, std::byte{'S'}, std::byte{'U'}};
    if (data.size() < magic.size() ||
        !std::ranges::equal(data.subspan(0, magic.size()), magic)) {
        return fail("invalid tree encoding");
    }

    wire::Reader reader{data.subspan(magic.size())};
    auto decoded_height = wire::read<std::uint64_t>(reader);
    if (!decoded_height) {
        return fail("truncated tree root");
    }
    height = *decoded_height;

    struct Pending {
        std::string path;
        std::uint32_t remaining;
        std::uint32_t depth;
    };
    std::uint32_t root_children = 0;
    Snapshot snapshot;

    auto read_row =
        [&](std::string path,
            std::uint32_t& child_count) -> std::expected<NodeRow, Error> {
        auto hash = wire::read_array<32>(reader);
        auto size = wire::read<std::uint64_t>(reader);
        auto nanos = wire::read<std::int64_t>(reader);
        auto is_directory = wire::read<std::uint8_t>(reader);
        auto children = wire::read<std::uint32_t>(reader);
        if (!hash || !size || !nanos || !is_directory || !children) {
            return fail("truncated tree row");
        }
        if (*is_directory > 1) {
            return fail("invalid tree node type");
        }
        child_count = *children;
        if (static_cast<std::uint64_t>(child_count) * 29ULL >
            reader.data.size()) {
            return fail("forged tree child count");
        }
        if (*is_directory == 0 && child_count != 0) {
            return fail("file has tree children");
        }
        return NodeRow{.path = std::move(path),
                       .hash = *hash,
                       .size = *size,
                       .mtime = *nanos,
                       .is_directory = *is_directory == 1};
    };

    auto root_name = wire::read_string(reader);
    if (!root_name || !root_name->empty()) {
        return fail("invalid tree root name");
    }
    auto root = read_row("", root_children);
    if (!root) {
        return std::unexpected(root.error());
    }
    if (!root->is_directory) {
        return fail("tree root is not a directory");
    }
    snapshot.rows.push_back(std::move(*root));

    std::vector<Pending> stack;
    if (root_children) {
        stack.push_back({"", root_children, 0});
    }
    while (!stack.empty()) {
        auto& parent = stack.back();
        auto name = wire::read_string(reader);
        if (!name || !valid_logical_path_component(*name)) {
            return fail("invalid tree path component");
        }
        const auto path =
            parent.path.empty() ? *name : parent.path + '/' + *name;
        const auto depth = parent.depth + 1;
        if (depth > 256) {
            return fail("tree depth exceeds limit");
        }
        if (--parent.remaining == 0) {
            stack.pop_back();
        }
        std::uint32_t children = 0;
        auto row = read_row(path, children);
        if (!row) {
            return std::unexpected(row.error());
        }
        snapshot.rows.push_back(std::move(*row));
        if (children) {
            stack.push_back({path, children, depth});
        }
    }

    if (!reader.data.empty()) {
        return fail("trailing tree bytes");
    }
    std::ranges::sort(snapshot.rows, path_less, &NodeRow::path);
    const auto duplicate = std::ranges::adjacent_find(
        snapshot.rows, [](const NodeRow& left, const NodeRow& right) {
            return left.path == right.path;
        });
    if (duplicate != snapshot.rows.end()) {
        return fail("duplicate tree path");
    }
    return snapshot;
}

template <typename Fn> void for_each_ancestor(std::string_view path, Fn&& fn) {
    while (!path.empty()) {
        path = row_parent(path);
        fn(path);
    }
}

bool same_state(const NodeRow* left, const NodeRow* right) {
    if (!left && !right) {
        return true;
    }
    if (!left || !right || left->is_directory != right->is_directory) {
        return false;
    }
    return left->is_directory ||
           (left->hash == right->hash && left->size == right->size);
}

std::expected<void, Error>
validate_snapshot_structure(const Snapshot& snapshot) {
    if (!valid_snapshot(snapshot, false)) {
        return std::unexpected(
            Error{ErrorCode::InvalidSnapshot, "invalid snapshot"});
    }
    return {};
}

std::expected<void, Error> validate_dag(const Index& index) {
    enum class Color {
        White,
        Gray,
        Black
    };
    struct Frame {
        std::string id;
        std::size_t next_parent = 0;
        std::size_t depth = 0;
    };

    std::unordered_map<std::string, Color> colors;
    for (const auto& [id, commit] : index) {
        static_cast<void>(commit);
        colors.emplace(id, Color::White);
    }

    for (const auto& [root, unused] : index) {
        static_cast<void>(unused);
        if (colors.at(root) != Color::White) {
            continue;
        }

        std::vector<Frame> stack{{root, 0, 0}};
        while (!stack.empty()) {
            auto& frame = stack.back();
            if (frame.depth > maximum_graph_depth) {
                return std::unexpected(Error{ErrorCode::LimitExceeded,
                                             "maximum graph depth exceeded"});
            }
            colors.at(frame.id) = Color::Gray;
            const auto& parents = index.at(frame.id)->commit.parents;
            if (frame.next_parent == parents.size()) {
                colors.at(frame.id) = Color::Black;
                stack.pop_back();
                continue;
            }

            const auto& parent = parents[frame.next_parent++];
            if (index.at(parent)->commit.created_at >
                index.at(frame.id)->commit.created_at) {
                return std::unexpected(Error{ErrorCode::InvalidCommit,
                                             "timestamp regression detected"});
            }
            switch (colors.at(parent)) {
                case Color::Gray:
                    return std::unexpected(
                        Error{ErrorCode::Cycle, "cycle detected in graph"});
                case Color::Black:
                    break;
                case Color::White:
                    stack.push_back({parent, 0, frame.depth + 1});
                    break;
            }
        }
    }
    return {};
}

std::expected<std::unordered_set<std::string>, Error>
collect_ancestors(const Index& index, const std::string& head) {
    std::unordered_set<std::string> result;
    std::vector<std::pair<std::string, std::size_t>> stack{{head, 0}};
    while (!stack.empty()) {
        auto [id, depth] = std::move(stack.back());
        stack.pop_back();
        if (depth > maximum_graph_depth) {
            return std::unexpected(
                Error{ErrorCode::LimitExceeded, "graph depth exceeded"});
        }
        if (!result.insert(id).second) {
            continue;
        }
        if (result.size() > maximum_loaded_commit_count) {
            return std::unexpected(
                Error{ErrorCode::LimitExceeded, "ancestor count exceeded"});
        }
        for (const auto& parent : index.at(id)->commit.parents) {
            stack.emplace_back(parent, depth + 1);
        }
    }
    return result;
}

std::expected<std::vector<std::string>, Error> find_best_common_ancestors(
    const Index& index,
    const std::unordered_set<std::string>& common_ancestors) {
    if (common_ancestors.empty()) {
        return std::vector<std::string>{};
    }

    std::unordered_set<std::string_view> parent_of_common;
    for (const auto& candidate : common_ancestors) {
        for (const auto& parent : index.at(candidate)->commit.parents) {
            parent_of_common.insert(parent);
        }
    }

    std::vector<std::string> best;
    for (const auto& candidate : common_ancestors) {
        if (!parent_of_common.contains(candidate)) {
            best.push_back(candidate);
        }
    }

    std::ranges::sort(best);
    return best;
}

struct HeadChanges {
    std::string head_id;
    const Snapshot* tree = nullptr;
    PathSet directly_changed;
    PathSet changed_subtrees;
};

HeadChanges build_head_changes(const Snapshot& base,
                               const std::string& head_id,
                               const Snapshot& head) {
    HeadChanges changes{.head_id = head_id,
                        .tree = &head,
                        .directly_changed = {},
                        .changed_subtrees = {}};
    std::size_t base_index = 0;
    std::size_t head_index = 0;
    while (base_index < base.rows.size() || head_index < head.rows.size()) {
        const NodeRow* base_row = nullptr;
        const NodeRow* head_row = nullptr;
        if (head_index == head.rows.size() ||
            (base_index < base.rows.size() &&
             path_less(base.rows[base_index].path,
                       head.rows[head_index].path))) {
            base_row = &base.rows[base_index++];
        } else if (base_index == base.rows.size() ||
                   path_less(head.rows[head_index].path,
                             base.rows[base_index].path)) {
            head_row = &head.rows[head_index++];
        } else {
            base_row = &base.rows[base_index++];
            head_row = &head.rows[head_index++];
        }
        if (same_state(base_row, head_row)) {
            continue;
        }
        const std::string& path =
            base_row != nullptr ? base_row->path : head_row->path;
        changes.directly_changed.insert(path);
        for_each_ancestor(path, [&](std::string_view ancestor) {
            changes.changed_subtrees.emplace(ancestor);
        });
    }
    return changes;
}

std::vector<HeadChanges>
build_merge_changes(const Index& index,
                    const Snapshot& base,
                    const std::vector<std::string>& ids,
                    const PathSet* uncertain = nullptr) {
    std::vector<HeadChanges> changes;
    changes.reserve(ids.size());
    for (const auto& id : ids) {
        changes.push_back(
            build_head_changes(base, id, index.at(id)->commit.tree));
    }
    if (uncertain) {
        for (const auto& path : *uncertain) {
            const auto* first = find_row(*changes.front().tree, path);
            if (std::ranges::all_of(changes, [&](const auto& head) {
                    return same_state(first, find_row(*head.tree, path));
                })) {
                continue;
            }
            // Equality with an arbitrary virtual winner is not causal
            // agreement.
            for (auto& head : changes) {
                head.directly_changed.insert(path);
                for_each_ancestor(path, [&](std::string_view ancestor) {
                    head.changed_subtrees.emplace(ancestor);
                });
            }
        }
    }
    return changes;
}

bool conflict_path_is_safe(std::string_view candidate,
                           const std::map<std::string, bool>& reserved) {
    const auto key_candidate = portable_case_key(candidate);
    for (const auto& [path, is_directory] : reserved) {
        const auto key_path = portable_case_key(path);
        if (key_path == key_candidate ||
            is_descendant(key_path, key_candidate) ||
            (!is_directory && is_descendant(key_candidate, key_path))) {
            return false;
        }
    }
    return true;
}

std::expected<std::string, Error>
select_conflict_path(std::string_view path,
                     std::string_view source_head_id,
                     std::map<std::string, bool>& reserved) {
    const std::string suffix_base =
        ".kasumiconflict_" + std::string(source_head_id.substr(0, 12));
    for (std::size_t suffix = 0;; ++suffix) {
        std::string suffix_str = suffix_base;
        if (suffix != 0) {
            suffix_str += '.' + std::to_string(suffix);
        }
        std::string candidate = make_conflict_path(path, suffix_str);
        if (conflict_path_is_safe(candidate, reserved)) {
            reserved.emplace(candidate, false);
            return candidate;
        }
        if (suffix == std::numeric_limits<std::size_t>::max()) {
            return std::unexpected(Error{ErrorCode::UnsafeMerge,
                                         "cannot find safe conflict path"});
        }
    }
}

std::expected<Snapshot, Error>
merge_snapshots(const Snapshot& base,
                const std::vector<HeadChanges>& heads,
                bool& has_conflicts,
                PathSet* conflict_paths = nullptr) {
    enum class VariantKind {
        Absent,
        File,
        Directory
    };
    struct Variant {
        VariantKind kind = VariantKind::Absent;
        std::optional<NodeRow> row;
        std::string source_head_id;
    };

    std::set<std::string> all_paths;
    std::map<std::string, bool> reserved;
    for (const auto& row : base.rows) {
        all_paths.insert(row.path);
        reserved.emplace(row.path, row.is_directory);
    }
    for (const auto& head : heads) {
        for (const auto& row : head.tree->rows) {
            all_paths.insert(row.path);
            reserved.emplace(row.path, row.is_directory);
        }
    }

    std::vector<NodeRow> final_rows;
    for (const auto& path : all_paths) {
        const auto* base_row = find_row(base, path);
        std::vector<Variant> variants;

        for (const auto& head : heads) {
            const auto* head_row = find_row(*head.tree, path);
            const bool active = head.directly_changed.contains(path) ||
                                (head_row && head_row->is_directory &&
                                 head.changed_subtrees.contains(path));
            if (!active) {
                continue;
            }

            auto existing =
                std::ranges::find_if(variants, [&](const Variant& variant) {
                    return same_state(variant.row ? &*variant.row : nullptr,
                                      head_row);
                });
            if (existing != variants.end()) {
                if (head_row && !head_row->is_directory && existing->row &&
                    head_row->mtime > existing->row->mtime) {
                    existing->row->mtime = head_row->mtime;
                }
                if (head.head_id < existing->source_head_id) {
                    existing->source_head_id = head.head_id;
                }
                continue;
            }

            variants.push_back(Variant{
                .kind = !head_row                ? VariantKind::Absent
                        : head_row->is_directory ? VariantKind::Directory
                                                 : VariantKind::File,
                .row = head_row ? std::make_optional(*head_row) : std::nullopt,
                .source_head_id = head.head_id});
        }

        if (variants.empty()) {
            if (base_row) {
                final_rows.push_back(*base_row);
            }
            continue;
        }
        if (variants.size() == 1) {
            if (variants.front().row) {
                final_rows.push_back(*variants.front().row);
            }
            continue;
        }

        has_conflicts = true;
        if (conflict_paths) {
            conflict_paths->insert(path);
            if (std::ranges::any_of(variants, [](const auto& variant) {
                    return variant.kind == VariantKind::Directory;
                })) {
                const auto prefix = path + '/';
                for (auto it = all_paths.lower_bound(prefix);
                     it != all_paths.end() && it->starts_with(prefix);
                     ++it) {
                    conflict_paths->insert(*it);
                }
            }
        }
        const auto rank = [](VariantKind kind) {
            switch (kind) {
                case VariantKind::Directory:
                    return 0;
                case VariantKind::File:
                    return 1;
                case VariantKind::Absent:
                    return 2;
            }
            return 3;
        };
        std::ranges::sort(variants,
                          [&](const Variant& left, const Variant& right) {
                              if (rank(left.kind) != rank(right.kind)) {
                                  return rank(left.kind) < rank(right.kind);
                              }
                              return left.source_head_id < right.source_head_id;
                          });

        if (variants.front().row) {
            final_rows.push_back(*variants.front().row);
        }
        for (std::size_t i = 1; i < variants.size(); ++i) {
            if (!variants[i].row) {
                continue;
            }
            auto conflict_path = select_conflict_path(
                path, variants[i].source_head_id, reserved);
            if (!conflict_path) {
                return std::unexpected(conflict_path.error());
            }
            auto conflict_row = *variants[i].row;
            conflict_row.path = *conflict_path;
            final_rows.push_back(std::move(conflict_row));
        }
    }

    std::unordered_set<std::string> final_paths;
    std::unordered_set<std::string> final_directories;
    for (const auto& row : final_rows) {
        if (!final_paths.insert(row.path).second) {
            return std::unexpected(
                Error{ErrorCode::UnsafeMerge, "duplicate path in merge"});
        }
        if (row.is_directory) {
            final_directories.insert(row.path);
        }
    }

    std::vector<NodeRow> synthesized_parents;
    bool ancestor_is_file = false;
    for (const auto& row : final_rows) {
        for_each_ancestor(row.path, [&](std::string_view ancestor) {
            const std::string ancestor_str{ancestor};
            if (final_paths.contains(ancestor_str)) {
                if (!final_directories.contains(ancestor_str)) {
                    ancestor_is_file = true;
                }
                return;
            }
            final_paths.insert(ancestor_str);
            final_directories.insert(ancestor_str);
            synthesized_parents.push_back(
                NodeRow{.path = ancestor_str, .is_directory = true});
        });
        if (ancestor_is_file) {
            return std::unexpected(
                Error{ErrorCode::UnsafeMerge, "ancestor is a file"});
        }
    }
    final_rows.insert(final_rows.end(),
                      std::make_move_iterator(synthesized_parents.begin()),
                      std::make_move_iterator(synthesized_parents.end()));

    if (!final_paths.contains("")) {
        final_rows.push_back(NodeRow{.path = "", .is_directory = true});
    } else if (!final_directories.contains("")) {
        return std::unexpected(
            Error{ErrorCode::UnsafeMerge, "root is not a directory"});
    }

    for (auto& row : final_rows) {
        if (row.is_directory) {
            row.hash = {};
            row.size = 0;
            row.mtime = {};
        }
    }

    Snapshot merged{.rows = std::move(final_rows)};
    finalize_snapshot(merged);
    return merged;
}

struct VirtualMergeBase {
    Snapshot tree;
    PathSet uncertain_paths;
};

std::expected<VirtualMergeBase, Error>
reconcile_merge_bases(const Index& index, std::vector<std::string> bases) {
    std::vector<std::vector<std::string>> layers;
    auto remaining_visits = maximum_virtual_base_ancestor_visits;
    while (bases.size() > 1) {
        if (bases.size() > maximum_parent_count ||
            layers.size() >= maximum_graph_depth) {
            return std::unexpected(Error{ErrorCode::LimitExceeded,
                                         "virtual merge base limit exceeded"});
        }
        std::unordered_set<std::string> common;
        for (std::size_t i = 0; i < bases.size(); ++i) {
            auto ancestors = collect_ancestors(index, bases[i]);
            if (!ancestors) {
                return std::unexpected(ancestors.error());
            }
            if (ancestors->size() > remaining_visits) {
                return std::unexpected(
                    Error{ErrorCode::LimitExceeded,
                          "virtual base ancestry budget exceeded"});
            }
            remaining_visits -= ancestors->size();
            if (i == 0) {
                common = std::move(*ancestors);
            } else {
                std::erase_if(common, [&](const auto& id) {
                    return !ancestors->contains(id);
                });
            }
        }
        auto next = find_best_common_ancestors(index, common);
        if (!next) {
            return std::unexpected(next.error());
        }
        if (next->empty()) {
            return std::unexpected(Error{ErrorCode::AmbiguousMergeBase,
                                         "cannot reconcile merge bases without "
                                         "common ancestry in loaded frontier"});
        }
        layers.push_back(std::move(bases));
        bases = std::move(*next);
    }

    VirtualMergeBase base{.tree = index.at(bases.front())->commit.tree,
                          .uncertain_paths = {}};
    for (auto layer = layers.rbegin(); layer != layers.rend(); ++layer) {
        const auto changes = build_merge_changes(
            index, base.tree, *layer, &base.uncertain_paths);
        bool base_conflicts = false;
        PathSet conflicts;
        auto merged =
            merge_snapshots(base.tree, changes, base_conflicts, &conflicts);
        if (!merged) {
            return std::unexpected(merged.error());
        }
        auto valid = validate_snapshot_structure(*merged);
        if (!valid) {
            return std::unexpected(
                Error{ErrorCode::UnsafeMerge, valid.error().detail});
        }
        base.tree = std::move(*merged);
        base.uncertain_paths = std::move(conflicts);
    }
    return base;
}

void write_storage_manifest(wire::Writer& writer,
                            const StorageManifest& manifest) {
    wire::write(writer,
                static_cast<std::uint32_t>(manifest.packed_blobs.size()));
    for (const auto& entry : manifest.packed_blobs) {
        wire::write_array(writer, entry.blob_hash);
        wire::write(writer, static_cast<std::uint64_t>(entry.size));
        wire::write_array(writer, entry.pack_hash);
    }
    wire::write(writer,
                static_cast<std::uint32_t>(manifest.chunked_files.size()));
    for (const auto& entry : manifest.chunked_files) {
        wire::write_array(writer, entry.file_hash);
        wire::write(writer, static_cast<std::uint64_t>(entry.file_size));
        wire::write(writer, static_cast<std::uint32_t>(entry.chunks.size()));
        for (const auto& chunk : entry.chunks) {
            wire::write_array(writer, chunk.hash);
            wire::write(writer, static_cast<std::uint32_t>(chunk.size));
        }
    }
}

std::expected<StorageManifest, Error>
read_storage_manifest(wire::Reader& reader) {
    const auto fail = [](ErrorCode code, const char* msg) {
        return std::unexpected(Error{code, msg});
    };

    auto packed_count = wire::read<std::uint32_t>(reader);
    if (!packed_count) {
        return fail(ErrorCode::InvalidEncoding, "truncated packed blob count");
    }
    if (*packed_count > maximum_packed_blob_entries ||
        static_cast<std::uint64_t>(*packed_count) * 72ULL >
            reader.data.size()) {
        return fail(ErrorCode::LimitExceeded,
                    "packed blob manifest exceeds bounds");
    }

    StorageManifest manifest;
    manifest.packed_blobs.reserve(*packed_count);
    for (std::uint32_t i = 0; i < *packed_count; ++i) {
        auto blob_hash = wire::read_array<HASH_SIZE>(reader);
        auto size = wire::read<std::uint64_t>(reader);
        auto pack_hash = wire::read_array<HASH_SIZE>(reader);
        if (!blob_hash || !size || !pack_hash ||
            *size > maximum_packed_blob_size) {
            return fail(ErrorCode::InvalidEncoding,
                        "truncated or oversized packed blob entry");
        }
        if (i > 0 && !(manifest.packed_blobs.back().blob_hash < *blob_hash)) {
            return fail(ErrorCode::InvalidEncoding,
                        "packed blobs not strictly sorted");
        }
        manifest.packed_blobs.push_back(PackedBlobEntry{
            .blob_hash = *blob_hash,
            .size = *size,
            .pack_hash = *pack_hash,
        });
    }

    auto chunked_count = wire::read<std::uint32_t>(reader);
    if (!chunked_count) {
        return fail(ErrorCode::InvalidEncoding, "truncated chunked file count");
    }
    if (*chunked_count > maximum_chunked_file_entries ||
        static_cast<std::uint64_t>(*chunked_count) * 44ULL >
            reader.data.size()) {
        return fail(ErrorCode::LimitExceeded,
                    "chunked file manifest exceeds bounds");
    }

    manifest.chunked_files.reserve(*chunked_count);
    for (std::uint32_t i = 0; i < *chunked_count; ++i) {
        auto file_hash = wire::read_array<HASH_SIZE>(reader);
        auto file_size = wire::read<std::uint64_t>(reader);
        auto chunk_count = wire::read<std::uint32_t>(reader);
        if (!file_hash || !file_size || !chunk_count) {
            return fail(ErrorCode::InvalidEncoding,
                        "truncated chunked file entry");
        }
        if (*chunk_count == 0 || *chunk_count > maximum_chunks_per_file ||
            static_cast<std::uint64_t>(*chunk_count) * 36ULL >
                reader.data.size()) {
            return fail(ErrorCode::LimitExceeded,
                        "chunk list exceeds bounds or is empty");
        }
        if (i > 0 && !(manifest.chunked_files.back().file_hash < *file_hash)) {
            return fail(ErrorCode::InvalidEncoding,
                        "chunked files not strictly sorted");
        }

        ChunkedFileEntry entry{.file_hash = *file_hash,
                               .file_size = *file_size,
                               .chunks = {}};
        entry.chunks.reserve(*chunk_count);
        std::uint64_t total_chunk_bytes = 0;
        for (std::uint32_t c = 0; c < *chunk_count; ++c) {
            auto chunk_hash = wire::read_array<HASH_SIZE>(reader);
            auto chunk_size = wire::read<std::uint32_t>(reader);
            if (!chunk_hash || !chunk_size) {
                return fail(ErrorCode::InvalidEncoding,
                            "truncated chunk entry");
            }
            if (*chunk_size == 0 || *chunk_size > maximum_chunk_slice_size ||
                *chunk_size > *file_size - total_chunk_bytes) {
                return fail(ErrorCode::InvalidEncoding,
                            "invalid chunk size sum");
            }
            total_chunk_bytes += *chunk_size;
            entry.chunks.push_back(ChunkSlice{
                .hash = *chunk_hash,
                .size = *chunk_size,
            });
        }
        if (total_chunk_bytes != *file_size) {
            return fail(ErrorCode::InvalidEncoding,
                        "chunked file size does not match chunks");
        }
        manifest.chunked_files.push_back(std::move(entry));
    }

    return manifest;
}

} // namespace

bool valid_storage_manifest(const StorageManifest& manifest,
                            const Snapshot& tree) noexcept {
    try {
        if (manifest.packed_blobs.size() > maximum_packed_blob_entries ||
            manifest.chunked_files.size() > maximum_chunked_file_entries) {
            return false;
        }
        if (manifest.empty()) {
            return true;
        }

        std::vector<std::pair<Hash, std::uint64_t>> live_files;
        live_files.reserve(tree.rows.size());
        for (const auto& row : tree.rows) {
            if (!row.is_directory && row.path != ".kasumiignore") {
                live_files.emplace_back(row.hash, row.size);
            }
        }
        std::ranges::sort(live_files);
        live_files.erase(std::ranges::unique(live_files).begin(),
                         live_files.end());

        for (std::size_t i = 0; i < manifest.packed_blobs.size(); ++i) {
            const auto& entry = manifest.packed_blobs[i];
            if (i > 0 &&
                !(manifest.packed_blobs[i - 1].blob_hash < entry.blob_hash)) {
                return false;
            }
            if (entry.size > maximum_packed_blob_size) {
                return false;
            }
            if (!std::ranges::binary_search(
                    live_files, std::pair{entry.blob_hash, entry.size})) {
                return false;
            }
        }

        for (std::size_t i = 0; i < manifest.chunked_files.size(); ++i) {
            const auto& entry = manifest.chunked_files[i];
            if (i > 0 &&
                !(manifest.chunked_files[i - 1].file_hash < entry.file_hash)) {
                return false;
            }
            if (find_packed_blob(manifest, entry.file_hash) != nullptr) {
                return false;
            }
            if (entry.chunks.empty() ||
                entry.chunks.size() > maximum_chunks_per_file) {
                return false;
            }
            std::uint64_t sum = 0;
            for (const auto& chunk : entry.chunks) {
                if (chunk.size == 0 || chunk.size > maximum_chunk_slice_size ||
                    chunk.size > entry.file_size - sum) {
                    return false;
                }
                sum += chunk.size;
            }
            if (sum != entry.file_size) {
                return false;
            }
            if (!std::ranges::binary_search(
                    live_files, std::pair{entry.file_hash, entry.file_size})) {
                return false;
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

const PackedBlobEntry* find_packed_blob(const StorageManifest& manifest,
                                        const Hash& blob_hash) noexcept {
    const auto it = std::ranges::lower_bound(
        manifest.packed_blobs, blob_hash, {}, &PackedBlobEntry::blob_hash);
    if (it != manifest.packed_blobs.end() && it->blob_hash == blob_hash) {
        return &*it;
    }
    return nullptr;
}

const ChunkedFileEntry* find_chunked_file(const StorageManifest& manifest,
                                          const Hash& file_hash) noexcept {
    const auto it = std::ranges::lower_bound(
        manifest.chunked_files, file_hash, {}, &ChunkedFileEntry::file_hash);
    if (it != manifest.chunked_files.end() && it->file_hash == file_hash) {
        return &*it;
    }
    return nullptr;
}

BytesResult serialize_storage_manifest(const StorageManifest& manifest) {
    try {
        wire::Writer writer;
        write_storage_manifest(writer, manifest);
        if (writer.buffer.size() > maximum_commit_plaintext_size) {
            return std::unexpected(
                Error{ErrorCode::LimitExceeded, "manifest exceeds max size"});
        }
        std::vector<std::uint8_t> result(writer.buffer.size());
        if (!result.empty()) {
            std::memcpy(
                result.data(), writer.buffer.data(), writer.buffer.size());
        }
        return result;
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            Error{ErrorCode::LimitExceeded, "allocation failed"});
    } catch (...) {
        return std::unexpected(
            Error{ErrorCode::InvalidEncoding, "exception encoding manifest"});
    }
}

std::expected<StorageManifest, Error>
deserialize_storage_manifest(std::span<const std::uint8_t> bytes,
                             const Snapshot& tree) {
    if (bytes.size() > maximum_commit_plaintext_size) {
        return std::unexpected(
            Error{ErrorCode::LimitExceeded, "manifest exceeds max size"});
    }
    try {
        wire::Reader reader{
            {reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()}};
        auto manifest = read_storage_manifest(reader);
        if (!manifest) {
            return std::unexpected(manifest.error());
        }
        if (!reader.data.empty()) {
            return std::unexpected(Error{ErrorCode::InvalidEncoding,
                                         "trailing bytes in storage manifest"});
        }
        if (!valid_storage_manifest(*manifest, tree)) {
            return std::unexpected(Error{ErrorCode::InvalidCommit,
                                         "storage manifest invalid for tree"});
        }
        return manifest;
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            Error{ErrorCode::LimitExceeded, "allocation failed"});
    } catch (...) {
        return std::unexpected(
            Error{ErrorCode::InvalidEncoding, "exception decoding manifest"});
    }
}

StorageManifest
filter_and_merge_storage_manifests(const Snapshot& tree,
                                   std::span<const StorageManifest> manifests) {
    StorageManifest merged;
    if (std::ranges::all_of(manifests, [](const auto& m) {
            return m.empty();
        })) {
        return merged;
    }

    std::unordered_map<Hash, std::uint64_t, decltype(&hash_key)> live{
        0, hash_key};
    live.reserve(tree.rows.size());
    for (const auto& row : tree.rows) {
        if (!row.is_directory && row.path != ".kasumiignore") {
            live.emplace(row.hash, row.size);
        }
    }
    if (live.empty()) {
        return merged;
    }

    std::unordered_map<Hash, PackedBlobEntry, decltype(&hash_key)> packed_map{
        0, hash_key};
    std::unordered_map<Hash, ChunkedFileEntry, decltype(&hash_key)> chunked_map{
        0, hash_key};

    for (const auto& candidate : manifests) {
        for (const auto& entry : candidate.packed_blobs) {
            const auto found_live = live.find(entry.blob_hash);
            if (found_live == live.end() || found_live->second != entry.size) {
                continue;
            }
            auto [it, inserted] = packed_map.try_emplace(entry.blob_hash, entry);
            if (!inserted && entry.pack_hash < it->second.pack_hash) {
                it->second = entry;
            }
        }
        for (const auto& entry : candidate.chunked_files) {
            const auto found_live = live.find(entry.file_hash);
            if (found_live == live.end() ||
                found_live->second != entry.file_size ||
                entry.chunks.empty()) {
                continue;
            }
            auto [it, inserted] =
                chunked_map.try_emplace(entry.file_hash, entry);
            if (!inserted) {
                const bool smaller = std::ranges::lexicographical_compare(
                    entry.chunks,
                    it->second.chunks,
                    [](const ChunkSlice& a, const ChunkSlice& b) {
                        return a.hash != b.hash ? a.hash < b.hash
                                                : a.size < b.size;
                    });
                if (smaller) {
                    it->second = entry;
                }
            }
        }
    }

    merged.packed_blobs.reserve(packed_map.size());
    for (auto& [unused, entry] : packed_map) {
        static_cast<void>(unused);
        merged.packed_blobs.push_back(std::move(entry));
    }
    std::ranges::sort(merged.packed_blobs, {}, &PackedBlobEntry::blob_hash);

    merged.chunked_files.reserve(chunked_map.size());
    for (auto& [unused, entry] : chunked_map) {
        static_cast<void>(unused);
        if (!packed_map.contains(entry.file_hash)) {
            merged.chunked_files.push_back(std::move(entry));
        }
    }
    std::ranges::sort(merged.chunked_files, {}, &ChunkedFileEntry::file_hash);
    return merged;
}

bool valid_commit_id(std::string_view id) noexcept {
    return id.size() == HASH_HEX_SIZE && is_lowercase_hex(id);
}

std::expected<void, Error>
validate_parent_ids(std::span<const std::string> parents, bool require_sorted) {
    if (parents.size() > maximum_parent_count) {
        return std::unexpected(
            Error{ErrorCode::LimitExceeded, "too many parents"});
    }
    std::string_view previous;
    for (const auto& parent : parents) {
        if (!valid_commit_id(parent)) {
            return std::unexpected(
                Error{ErrorCode::InvalidParent, "invalid parent id"});
        }
        if (require_sorted && !previous.empty() && parent <= previous) {
            return std::unexpected(Error{ErrorCode::InvalidParent,
                                         "parents not sorted or duplicate"});
        }
        previous = parent;
    }
    return {};
}

namespace {

bool is_valid_utf8(std::string_view text) noexcept {
    std::size_t i = 0;
    while (i < text.size()) {
        const auto lead = static_cast<unsigned char>(text[i]);
        if (lead <= 0x7FU) {
            ++i;
            continue;
        }
        std::size_t count = 0;
        std::uint32_t code = 0;
        std::uint32_t min_code = 0;
        if ((lead & 0xE0U) == 0xC0U) {
            count = 1;
            code = lead & 0x1FU;
            min_code = 0x80U;
        } else if ((lead & 0xF0U) == 0xE0U) {
            count = 2;
            code = lead & 0x0FU;
            min_code = 0x800U;
        } else if ((lead & 0xF8U) == 0xF0U) {
            count = 3;
            code = lead & 0x07U;
            min_code = 0x10000U;
        } else {
            return false;
        }
        if (i + count >= text.size()) {
            return false;
        }
        for (std::size_t j = 1; j <= count; ++j) {
            const auto cont = static_cast<unsigned char>(text[i + j]);
            if ((cont & 0xC0U) != 0x80U) {
                return false;
            }
            code = (code << 6U) | (cont & 0x3FU);
        }
        if (code < min_code || code > 0x10FFFFU ||
            (code >= 0xD800U && code <= 0xDFFFU)) {
            return false;
        }
        i += count + 1;
    }
    return true;
}

} // namespace

bool has_commit_authorship(const CommitAuthorship& authorship) noexcept {
    const bool any_id = std::ranges::any_of(
        authorship.machine_id, [](std::uint8_t b) { return b != 0U; });
    return authorship.operation != CommitOriginOperation::Unknown || any_id ||
           !authorship.machine_name.empty();
}

bool valid_commit_authorship(const CommitAuthorship& authorship) noexcept {
    const auto op_raw = static_cast<std::uint8_t>(authorship.operation);
    if (op_raw > static_cast<std::uint8_t>(CommitOriginOperation::ResolveMissing)) {
        return false;
    }
    if (!has_commit_authorship(authorship)) {
        return true;
    }
    if (authorship.machine_name.size() > maximum_machine_name_bytes) {
        return false;
    }
    for (const auto ch : authorship.machine_name) {
        const auto byte = static_cast<unsigned char>(ch);
        if (byte < 0x20U || byte == 0x7FU) {
            return false;
        }
    }
    if (!is_valid_utf8(authorship.machine_name)) {
        return false;
    }
    const bool any_id = std::ranges::any_of(
        authorship.machine_id, [](std::uint8_t b) { return b != 0U; });
    if (authorship.operation != CommitOriginOperation::Unknown && !any_id) {
        return false;
    }
    return true;
}

CommitResult make_commit(std::uint64_t height,
                         std::vector<std::string> parents,
                         Snapshot tree,
                         std::int64_t created_at,
                         StorageManifest storage,
                         CommitAuthorship authorship) {
    try {
        if (auto valid = validate_parent_ids(parents, false); !valid) {
            return std::unexpected(valid.error());
        }
        std::ranges::sort(parents);
        if (std::ranges::adjacent_find(parents) != parents.end()) {
            return std::unexpected(
                Error{ErrorCode::InvalidParent, "duplicate parent"});
        }
        auto valid = validate_snapshot_structure(tree);
        if (!valid) {
            return std::unexpected(valid.error());
        }
        if (!valid_storage_manifest(storage, tree)) {
            return std::unexpected(
                Error{ErrorCode::InvalidCommit, "invalid storage manifest"});
        }
        if (!valid_commit_authorship(authorship)) {
            return std::unexpected(
                Error{ErrorCode::InvalidCommit, "invalid commit authorship"});
        }
        return Commit{.height = height,
                      .created_at = created_at,
                      .parents = std::move(parents),
                      .tree = std::move(tree),
                      .storage = std::move(storage),
                      .authorship = std::move(authorship)};
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            Error{ErrorCode::LimitExceeded, "allocation failed"});
    } catch (...) {
        return std::unexpected(
            Error{ErrorCode::InvalidCommit, "exception in make_commit"});
    }
}

CommitResult make_bootstrap(Snapshot tree,
                            std::uint64_t height,
                            std::int64_t created_at,
                            StorageManifest storage,
                            CommitAuthorship authorship) {
    return make_commit(height,
                       {},
                       std::move(tree),
                       created_at,
                       std::move(storage),
                       std::move(authorship));
}

CommitResult make_empty_bootstrap(std::int64_t created_at) {
    try {
        Snapshot tree{.rows = {NodeRow{.path = "", .is_directory = true}}};
        finalize_snapshot(tree);
        return make_bootstrap(std::move(tree), 0, created_at);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            Error{ErrorCode::LimitExceeded, "allocation failed"});
    } catch (...) {
        return std::unexpected(Error{ErrorCode::InvalidCommit,
                                     "exception in make_empty_bootstrap"});
    }
}

BytesResult serialize(const Commit& commit) {
    try {
        auto valid = validate_snapshot_structure(commit.tree);
        if (!valid) {
            return std::unexpected(valid.error());
        }
        if (auto parents_valid = validate_parent_ids(commit.parents, true);
            !parents_valid) {
            return std::unexpected(parents_valid.error());
        }

        if (auto valid_manifest =
                valid_storage_manifest(commit.storage, commit.tree);
            !valid_manifest) {
            return std::unexpected(
                Error{ErrorCode::InvalidCommit, "invalid storage manifest"});
        }
        if (!valid_commit_authorship(commit.authorship)) {
            return std::unexpected(
                Error{ErrorCode::InvalidCommit, "invalid commit authorship"});
        }

        auto tree_bytes = serialize_tree(commit.tree, commit.height);
        if (tree_bytes.size() > maximum_commit_plaintext_size) {
            return std::unexpected(Error{ErrorCode::LimitExceeded,
                                         "tree size exceeds maximum size"});
        }

        wire::Writer writer;
        wire::write_array(writer,
                          std::array<std::byte, 4>{std::byte{'K'},
                                                   std::byte{'C'},
                                                   std::byte{'O'},
                                                   std::byte{'M'}});
        wire::write(writer, commit_format_version);
        wire::write(writer, static_cast<uint64_t>(commit.height));
        wire::write<int64_t>(writer, commit.created_at);
        wire::write(writer, static_cast<uint32_t>(commit.parents.size()));
        for (const auto& parent : commit.parents) {
            auto hash = hash_from_hex(parent);
            if (!hash) {
                return std::unexpected(
                    Error{ErrorCode::InvalidParent, "invalid parent hex"});
            }
            wire::write_array(writer, *hash);
        }
        wire::write(writer, static_cast<uint64_t>(tree_bytes.size()));
        wire::write_bytes(writer, tree_bytes);
        write_storage_manifest(writer, commit.storage);
        wire::write(writer,
                    static_cast<std::uint8_t>(commit.authorship.operation));
        wire::write_bytes(
            writer, std::as_bytes(std::span{commit.authorship.machine_id}));
        wire::write_string(writer, commit.authorship.machine_name);
        if (writer.buffer.size() > maximum_commit_plaintext_size) {
            return std::unexpected(
                Error{ErrorCode::LimitExceeded, "commit exceeds maximum size"});
        }

        std::vector<uint8_t> result(writer.buffer.size());
        std::memcpy(result.data(), writer.buffer.data(), writer.buffer.size());
        return result;
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            Error{ErrorCode::LimitExceeded, "allocation failed"});
    } catch (...) {
        return std::unexpected(
            Error{ErrorCode::InvalidEncoding, "exception in serialize"});
    }
}

CommitResult deserialize(std::span<const std::uint8_t> bytes) {
    const auto fail = [](ErrorCode code, const char* msg) {
        return std::unexpected(Error{code, msg});
    };
    if (bytes.size() > maximum_commit_plaintext_size) {
        return fail(ErrorCode::LimitExceeded, "commit exceeds maximum size");
    }
    try {
        wire::Reader reader{
            {reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()}};
        auto magic = wire::read_array<4>(reader);
        if (!magic || *magic != std::array<std::byte, 4>{std::byte{'K'},
                                                         std::byte{'C'},
                                                         std::byte{'O'},
                                                         std::byte{'M'}}) {
            return fail(ErrorCode::InvalidEncoding,
                        magic ? "invalid magic" : "truncated magic");
        }
        auto version = wire::read<uint8_t>(reader);
        if (!version || *version != commit_format_version) {
            return fail(version ? ErrorCode::UnsupportedVersion
                                : ErrorCode::InvalidEncoding,
                        version ? "unsupported version" : "truncated version");
        }
        auto height = wire::read<uint64_t>(reader);
        auto created_at = wire::read<int64_t>(reader);
        auto parent_count = wire::read<uint32_t>(reader);
        if (!height || !created_at || !parent_count) {
            return fail(ErrorCode::InvalidEncoding, "truncated header");
        }
        if (*parent_count > maximum_parent_count) {
            return fail(ErrorCode::LimitExceeded, "too many parents");
        }

        std::vector<std::string> parents;
        parents.reserve(*parent_count);
        for (uint32_t i = 0; i < *parent_count; ++i) {
            auto parent_bytes = wire::read_array<32>(reader);
            if (!parent_bytes) {
                return fail(ErrorCode::InvalidEncoding, "truncated parent");
            }
            auto parent = hash_hex(*parent_bytes);
            if (!parents.empty() && parent <= parents.back()) {
                return fail(ErrorCode::InvalidParent,
                            "parents not strictly increasing");
            }
            parents.push_back(std::move(parent));
        }

        auto tree_size = wire::read<uint64_t>(reader);
        if (!tree_size) {
            return fail(ErrorCode::InvalidEncoding, "truncated tree size");
        }
        if (*tree_size > maximum_commit_plaintext_size) {
            return fail(ErrorCode::LimitExceeded, "tree size exceeds limits");
        }
        auto tree_bytes =
            wire::read_bytes(reader, static_cast<std::size_t>(*tree_size));
        if (!tree_bytes) {
            return fail(ErrorCode::InvalidEncoding, "truncated tree");
        }

        auto parsed_manifest = read_storage_manifest(reader);
        if (!parsed_manifest) {
            return std::unexpected(parsed_manifest.error());
        }
        StorageManifest storage = std::move(*parsed_manifest);

        auto raw_op = wire::read<std::uint8_t>(reader);
        auto machine_id_bytes =
            wire::read_array<machine_id_byte_count>(reader);
        auto machine_name =
            wire::read_string(reader, maximum_machine_name_bytes);
        if (!raw_op || !machine_id_bytes || !machine_name) {
            return fail(ErrorCode::InvalidEncoding,
                        "truncated commit authorship");
        }
        if (!reader.data.empty()) {
            return fail(ErrorCode::InvalidEncoding, "trailing bytes");
        }

        CommitAuthorship authorship;
        authorship.operation = static_cast<CommitOriginOperation>(*raw_op);
        for (std::size_t i = 0; i < machine_id_byte_count; ++i) {
            authorship.machine_id[i] =
                std::to_integer<std::uint8_t>((*machine_id_bytes)[i]);
        }
        authorship.machine_name = std::move(*machine_name);
        if (!valid_commit_authorship(authorship)) {
            return fail(ErrorCode::InvalidCommit, "invalid commit authorship");
        }

        uint64_t generation = 0;
        auto tree = deserialize_tree(*tree_bytes, generation);
        if (!tree) {
            return std::unexpected(tree.error());
        }
        if (generation != *height) {
            return fail(ErrorCode::InvalidEncoding,
                        "tree height does not match commit height");
        }
        if (auto valid = validate_snapshot_structure(*tree); !valid) {
            return std::unexpected(valid.error());
        }
        if (!valid_storage_manifest(storage, *tree)) {
            return fail(ErrorCode::InvalidCommit,
                        "commit storage manifest does not match tree");
        }
        return Commit{.height = *height,
                      .created_at = *created_at,
                      .parents = std::move(parents),
                      .tree = std::move(*tree),
                      .storage = std::move(storage),
                      .authorship = std::move(authorship)};
    } catch (const std::bad_alloc&) {
        return fail(ErrorCode::LimitExceeded, "allocation failed");
    } catch (...) {
        return fail(ErrorCode::InvalidEncoding, "exception in deserialize");
    }
}

StringResult compute_id(std::span<const std::uint8_t> canonical_bytes) {
    try {
        if (canonical_bytes.size() > maximum_commit_plaintext_size) {
            return std::unexpected(
                Error{ErrorCode::LimitExceeded, "commit exceeds maximum size"});
        }
        return hash_hex(kasumi::hasher::hash_bytes(canonical_bytes.data(),
                                                   canonical_bytes.size()));
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            Error{ErrorCode::LimitExceeded, "allocation failed"});
    } catch (...) {
        return std::unexpected(
            Error{ErrorCode::InvalidEncoding, "exception in compute_id"});
    }
}

StringResult compute_id(const Commit& commit) {
    auto bytes = serialize(commit);
    if (!bytes)
        return std::unexpected(bytes.error());
    return compute_id(*bytes);
}

static ResolutionResult
resolve_impl(std::span<const LoadedCommit> commits,
             std::span<const std::string> marked_heads,
             std::span<const std::string> trusted_anchor_ids,
             bool identifiers_authenticated) {
    try {
        if (commits.size() > maximum_loaded_commit_count) {
            return std::unexpected(
                Error{ErrorCode::LimitExceeded, "commit limit exceeded"});
        }
        if (marked_heads.empty()) {
            return std::unexpected(
                Error{ErrorCode::InvalidHead, "marked heads list is empty"});
        }
        if (marked_heads.size() > maximum_marked_head_count) {
            return std::unexpected(
                Error{ErrorCode::LimitExceeded, "too many marked heads"});
        }

        std::vector<std::string> unique_heads(marked_heads.begin(),
                                              marked_heads.end());
        std::ranges::sort(unique_heads);
        unique_heads.erase(std::ranges::unique(unique_heads).begin(),
                           unique_heads.end());
        for (const auto& head : unique_heads) {
            if (!valid_commit_id(head))
                return std::unexpected(
                    Error{ErrorCode::InvalidHead, "invalid head identifier"});
        }

        std::unordered_set<std::string> trusted_anchors;
        for (const auto& trusted_anchor_id : trusted_anchor_ids) {
            if (!valid_commit_id(trusted_anchor_id) ||
                !trusted_anchors.insert(trusted_anchor_id).second) {
                return std::unexpected(Error{ErrorCode::InvalidCommitId,
                                             "invalid trusted frontier"});
            }
        }

        Index index;
        std::size_t found_trusted_anchors = 0;
        for (const auto& loaded : commits) {
            if (!index.emplace(loaded.id, &loaded).second) {
                return std::unexpected(Error{ErrorCode::DuplicateCommit,
                                             "duplicate commit in input"});
            }
            auto valid = validate_snapshot_structure(loaded.commit.tree);
            if (!valid)
                return std::unexpected(valid.error());
            if (!valid_storage_manifest(loaded.commit.storage,
                                        loaded.commit.tree)) {
                return std::unexpected(
                    Error{ErrorCode::InvalidCommit,
                          "commit storage manifest is invalid for snapshot"});
            }
            if (trusted_anchors.contains(loaded.id)) {
                if (!loaded.commit.parents.empty()) {
                    return std::unexpected(
                        Error{ErrorCode::InvalidParent,
                              "trusted anchor must terminate loaded graph"});
                }
                ++found_trusted_anchors;
            } else if (!identifiers_authenticated) {
                auto computed = compute_id(loaded.commit);
                if (!computed)
                    return std::unexpected(computed.error());
                if (*computed != loaded.id)
                    return std::unexpected(
                        Error{ErrorCode::InvalidCommitId,
                              "id does not match commit content"});
            }
        }
        if (found_trusted_anchors != trusted_anchors.size()) {
            return std::unexpected(
                Error{ErrorCode::MissingParent, "trusted frontier missing"});
        }
        for (const auto& head : unique_heads) {
            if (!index.contains(head))
                return std::unexpected(
                    Error{ErrorCode::InvalidHead,
                          "head not found in loaded commits"});
        }

        for (const auto& [id, loaded] : index) {
            if (loaded->commit.parents.size() > maximum_parent_count) {
                return std::unexpected(Error{ErrorCode::LimitExceeded,
                                             "too many parents in commit"});
            }
            if (loaded->commit.parents.empty()) {
                if (!trusted_anchors.contains(id) &&
                    loaded->commit.height != 0) {
                    return std::unexpected(
                        Error{ErrorCode::HeightMismatch,
                              "untrusted root commit must have height zero"});
                }
                continue;
            }
            std::uint64_t max_parent_height = 0;
            for (const auto& parent : loaded->commit.parents) {
                const auto it = index.find(parent);
                if (it == index.end())
                    return std::unexpected(
                        Error{ErrorCode::MissingParent,
                              "parent not found in loaded commits"});
                max_parent_height =
                    std::max(max_parent_height, it->second->commit.height);
            }
            if (max_parent_height ==
                std::numeric_limits<std::uint64_t>::max()) {
                return std::unexpected(
                    Error{ErrorCode::HeightMismatch,
                          "parent height overflows commit height"});
            }
            if (loaded->commit.height != max_parent_height + 1) {
                return std::unexpected(
                    Error{ErrorCode::HeightMismatch,
                          "height does not match max(parents) + 1"});
            }
            static_cast<void>(id);
        }
        auto dag_valid = validate_dag(index);
        if (!dag_valid)
            return std::unexpected(dag_valid.error());

        std::unordered_map<std::string, std::unordered_set<std::string>>
            ancestor_sets;
        for (const auto& head : unique_heads) {
            auto ancestors = collect_ancestors(index, head);
            if (!ancestors)
                return std::unexpected(ancestors.error());
            ancestor_sets.emplace(head, std::move(*ancestors));
        }

        std::vector<std::string> logical_heads;
        for (const auto& head : unique_heads) {
            bool stale = false;
            for (const auto& other : unique_heads) {
                if (head != other && ancestor_sets.at(other).contains(head)) {
                    stale = true;
                    break;
                }
            }
            if (!stale)
                logical_heads.push_back(head);
        }

        if (logical_heads.size() > maximum_parent_count)
            return std::unexpected(
                Error{ErrorCode::LimitExceeded,
                      "too many logical heads for a single merge commit "
                      "(parent limit exceeded)"});

        if (logical_heads.size() == 1) {
            const auto& head = logical_heads.front();
            return Resolution{.tree = index.at(head)->commit.tree,
                              .height = index.at(head)->commit.height,
                              .heads = {head},
                              .has_conflicts = false,
                              .storage = index.at(head)->commit.storage};
        }

        std::unordered_set<std::string> common_ancestors =
            ancestor_sets.at(logical_heads.front());
        for (std::size_t i = 1; i < logical_heads.size(); ++i) {
            const auto& ancestors = ancestor_sets.at(logical_heads[i]);
            std::erase_if(common_ancestors, [&](const auto& id) {
                return !ancestors.contains(id);
            });
        }
        if (common_ancestors.empty())
            return std::unexpected(
                Error{ErrorCode::NoCommonAncestor, "no common ancestor found"});

        auto best_bases = find_best_common_ancestors(index, common_ancestors);
        if (!best_bases)
            return std::unexpected(best_bases.error());
        if (best_bases->empty())
            return std::unexpected(
                Error{ErrorCode::NoCommonAncestor, "no common ancestor found"});
        std::optional<VirtualMergeBase> virtual_base;
        if (best_bases->size() > 1) {
            auto reconciled = reconcile_merge_bases(index, *best_bases);
            if (!reconciled) {
                return std::unexpected(reconciled.error());
            }
            virtual_base = std::move(*reconciled);
        }
        const auto& base = virtual_base
                               ? virtual_base->tree
                               : index.at(best_bases->front())->commit.tree;
        const auto changes = build_merge_changes(
            index,
            base,
            logical_heads,
            virtual_base ? &virtual_base->uncertain_paths : nullptr);

        bool has_conflicts = false;
        auto merged = merge_snapshots(base, changes, has_conflicts);
        if (!merged)
            return std::unexpected(merged.error());
        auto valid = validate_snapshot_structure(*merged);
        if (!valid)
            return std::unexpected(
                Error{ErrorCode::UnsafeMerge, valid.error().detail});

        std::uint64_t height = 0;
        for (const auto& head : logical_heads)
            height = std::max(height, index.at(head)->commit.height);
        std::vector<StorageManifest> candidate_manifests;
        std::unordered_set<std::string_view> seen_manifest_commits;
        for (const auto& head : logical_heads) {
            for (const auto& ancestor_id : ancestor_sets.at(head)) {
                if (seen_manifest_commits.insert(ancestor_id).second) {
                    const auto it = index.find(ancestor_id);
                    if (it != index.end() &&
                        !it->second->commit.storage.empty()) {
                        candidate_manifests.push_back(
                            it->second->commit.storage);
                    }
                }
            }
        }
        auto resolved_storage = filter_and_merge_storage_manifests(
            *merged, candidate_manifests);
        return Resolution{.tree = std::move(*merged),
                          .height = height,
                          .heads = std::move(logical_heads),
                          .has_conflicts = has_conflicts,
                          .storage = std::move(resolved_storage)};
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            Error{ErrorCode::LimitExceeded, "memory allocation failed"});
    } catch (...) {
        return std::unexpected(Error{ErrorCode::InvalidCommit,
                                     "exception during history resolution"});
    }
}

ResolutionResult resolve(std::span<const LoadedCommit> commits,
                         std::span<const std::string> marked_heads) {
    return resolve_impl(commits, marked_heads, {}, false);
}

ResolutionResult
resolve_authenticated(std::span<const LoadedCommit> commits,
                      std::span<const std::string> marked_heads) {
    return resolve_impl(commits, marked_heads, {}, true);
}

ResolutionResult
resolve_single_anchor(std::span<const LoadedCommit> commits,
                      std::span<const std::string> marked_heads,
                      std::string_view trusted_anchor_id,
                      bool authenticate) {
    if (trusted_anchor_id.empty()) {
        return std::unexpected(
            Error{ErrorCode::InvalidCommitId, "trusted anchor is empty"});
    }
    const std::array anchors{std::string{trusted_anchor_id}};
    return resolve_impl(commits, marked_heads, anchors, authenticate);
}

ResolutionResult resolve_from_anchor(std::span<const LoadedCommit> commits,
                                     std::span<const std::string> marked_heads,
                                     std::string_view trusted_anchor_id) {
    return resolve_single_anchor(
        commits, marked_heads, trusted_anchor_id, false);
}

ResolutionResult
resolve_from_anchor_authenticated(std::span<const LoadedCommit> commits,
                                  std::span<const std::string> marked_heads,
                                  std::string_view trusted_anchor_id) {
    return resolve_single_anchor(
        commits, marked_heads, trusted_anchor_id, true);
}

ResolutionResult resolve_from_frontier_authenticated(
    std::span<const LoadedCommit> commits,
    std::span<const std::string> marked_heads,
    std::span<const std::string> trusted_anchor_ids) {
    if (trusted_anchor_ids.empty()) {
        return std::unexpected(
            Error{ErrorCode::InvalidCommitId, "trusted frontier is empty"});
    }
    return resolve_impl(commits, marked_heads, trusted_anchor_ids, true);
}

} // namespace kasumi::history
