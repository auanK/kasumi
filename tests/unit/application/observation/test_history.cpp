#include "application/history_storage/epoch.hpp"
#include "application/history_storage/history_storage.hpp"
#include "application/observation/history.hpp"
#include "application/observation/history_detail.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <initializer_list>
#include <map>
#include <memory>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

using Key = std::array<std::uint8_t, kasumi::crypto::KEY_SIZE>;
using Commit = kasumi::history::Commit;
using ErrorCode = kasumi::application::observation::history::ErrorCode;
using StorageView = kasumi::application::observation::history::StorageView;
using TempWorkspace = kasumi::test::TempWorkspace;

Key test_key() {
    Key key{};
    for (std::size_t index = 0; index < key.size(); ++index) {
        key[index] = static_cast<std::uint8_t>(index + 1);
    }
    return key;
}

kasumi::Snapshot
make_tree(std::initializer_list<std::pair<std::string_view, std::string_view>>
              files) {
    kasumi::Snapshot tree;
    tree.rows.push_back({.path = "", .mtime = {}, .is_directory = true});
    for (const auto& [path, contents] : files) {
        tree.rows.push_back({.path = std::string{path},
                             .hash = kasumi::hasher::hash_string(contents),
                             .size = contents.size(),
                             .mtime = {},
                             .is_directory = false});
    }
    kasumi::finalize_snapshot(tree);
    return tree;
}

Commit make_commit(std::uint64_t height,
                   std::vector<std::string> parents,
                   kasumi::Snapshot tree) {
    auto result = kasumi::history::make_commit(
        height, std::move(parents), std::move(tree));
    EXPECT_TRUE(result.has_value());
    return result ? *result : Commit{};
}

std::string commit_id(const Commit& commit) {
    const auto canonical = kasumi::history::serialize(commit).value();
    return kasumi::crypto::commit_identifier(test_key(), canonical);
}

std::string
object_path(const kasumi::application::history_storage::HeadReference& head) {
    return "history/commits/" + head.commit_id + "/" + head.ciphertext_id +
           ".kcom";
}

std::string
marker_path(const kasumi::application::history_storage::HeadReference& head) {
    return "history/heads/" + head.commit_id + "-" + head.ciphertext_id +
           ".head";
}

bool same_tree(const kasumi::Snapshot& left, const kasumi::Snapshot& right) {
    if (left.rows.size() != right.rows.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.rows.size(); ++index) {
        const auto& a = left.rows[index];
        const auto& b = right.rows[index];
        if (a.path != b.path || a.hash != b.hash || a.size != b.size ||
            a.mtime != b.mtime || a.is_directory != b.is_directory) {
            return false;
        }
    }
    return true;
}

struct LocalStorage {
    TempWorkspace workspace;
    kasumi::transport::Transport transport;
};

LocalStorage make_local_storage() {
    LocalStorage storage{
        .workspace = kasumi::test::make_temp_workspace("observation-history"),
        .transport = {}};
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(storage.workspace, "storage").string());
    EXPECT_TRUE(opened.has_value());
    if (opened) {
        storage.transport = std::move(*opened);
        EXPECT_TRUE(kasumi::transport::initialize(storage.transport));
    }
    return storage;
}

struct FakeState {
    std::map<std::string, std::vector<std::uint8_t>> objects;
    std::size_t list_count = 0;
    std::size_t full_list_count = 0;
    std::size_t prefix_list_count = 0;
    std::size_t get_count = 0;
    std::size_t marker_get_count = 0;
    std::size_t commit_get_count = 0;
    std::size_t put_count = 0;
    std::size_t remove_count = 0;
    bool fail_first_list = false;
    bool fail_second_list = false;
    bool fail_marker_get = false;
    bool fail_commit_get = false;
    bool reverse_listing = false;
    bool directory_destination = false;
    std::string disappear_on_get;
};

void destroy_fake(void*) noexcept {
}

FakeState& fake_state(void* context) {
    return *static_cast<FakeState*>(context);
}

kasumi::transport::Error fake_error(std::string message) {
    return kasumi::transport::Error{
        .code = kasumi::transport::ErrorCode::Io,
        .message = std::move(message),
    };
}

bool is_marker(std::string_view identifier) {
    return identifier.starts_with("history/heads/");
}

bool is_commit(std::string_view identifier) {
    return identifier.starts_with("history/commits/");
}

kasumi::transport::Result fake_initialize(void*) {
    return {};
}

kasumi::transport::Result fake_put(void* context,
                                   const std::filesystem::path& source,
                                   std::string_view identifier) {
    auto& state = fake_state(context);
    std::error_code error;
    const auto size = std::filesystem::file_size(source, error);
    if (error) {
        return std::unexpected(fake_error("could not read source"));
    }
    std::ifstream input(source, std::ios::binary);
    if (!input) {
        return std::unexpected(fake_error("could not open source"));
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
    }
    if (!input) {
        return std::unexpected(fake_error("could not read source"));
    }
    ++state.put_count;
    state.objects[std::string{identifier}] = std::move(bytes);
    return {};
}

kasumi::transport::Result fake_get(void* context,
                                   std::string_view identifier,
                                   const std::filesystem::path& destination) {
    auto& state = fake_state(context);
    ++state.get_count;
    if (is_marker(identifier)) {
        ++state.marker_get_count;
    } else if (is_commit(identifier)) {
        ++state.commit_get_count;
    }
    if ((is_marker(identifier) && state.fail_marker_get) ||
        (is_commit(identifier) && state.fail_commit_get)) {
        return std::unexpected(fake_error("injected get failure"));
    }
    if (identifier == state.disappear_on_get) {
        state.objects.erase(std::string{identifier});
        state.disappear_on_get.clear();
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::ObjectNotFound,
            .message = "object disappeared",
        });
    }
    const auto found = state.objects.find(std::string{identifier});
    if (found == state.objects.end()) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::ObjectNotFound,
            .message = "object not found",
        });
    }
    if (state.directory_destination) {
        std::error_code error;
        std::filesystem::create_directories(destination, error);
        if (error) {
            return std::unexpected(fake_error("could not create destination"));
        }
        return {};
    }
    std::ofstream output(destination, std::ios::binary | std::ios::trunc);
    if (!output) {
        return std::unexpected(fake_error("could not create destination"));
    }
    const auto& bytes = found->second;
    if (!bytes.empty()) {
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
    }
    if (!output) {
        return std::unexpected(fake_error("could not write destination"));
    }
    return {};
}

kasumi::transport::PresenceResult fake_presence(void* context,
                                                std::string_view identifier) {
    auto& state = fake_state(context);
    return state.objects.contains(std::string{identifier})
               ? kasumi::transport::Presence::Present
               : kasumi::transport::Presence::Absent;
}

kasumi::transport::ListingResult fake_list(void* context) {
    auto& state = fake_state(context);
    ++state.list_count;
    ++state.full_list_count;
    if ((state.list_count == 1 && state.fail_first_list) ||
        (state.list_count == 2 && state.fail_second_list)) {
        return std::unexpected(fake_error("injected list failure"));
    }
    std::vector<std::string> result;
    result.reserve(state.objects.size());
    for (const auto& [identifier, unused] : state.objects) {
        static_cast<void>(unused);
        result.push_back(identifier);
    }
    if (state.reverse_listing) {
        std::ranges::reverse(result);
    }
    return result;
}

kasumi::transport::ListingResult fake_list_prefix(void* context,
                                                  std::string_view prefix) {
    auto& state = fake_state(context);
    ++state.list_count;
    ++state.prefix_list_count;
    if ((state.list_count == 1 && state.fail_first_list) ||
        (state.list_count == 2 && state.fail_second_list)) {
        return std::unexpected(fake_error("injected list failure"));
    }
    const auto full_prefix = std::string{prefix} + "/";
    std::vector<std::string> result;
    for (const auto& [identifier, unused] : state.objects) {
        static_cast<void>(unused);
        if (!identifier.starts_with(full_prefix)) {
            continue;
        }
        const auto name = identifier.substr(full_prefix.size());
        if (name.find('/') == std::string::npos) {
            result.push_back(name);
        }
    }
    if (state.reverse_listing) {
        std::ranges::reverse(result);
    }
    return result;
}

kasumi::transport::RemovalResult fake_remove(void* context,
                                             std::string_view identifier) {
    auto& state = fake_state(context);
    ++state.remove_count;
    return state.objects.erase(std::string{identifier}) != 0
               ? kasumi::transport::Removal::Removed
               : kasumi::transport::Removal::AlreadyAbsent;
}

kasumi::transport::Transport make_fake_transport(FakeState& state) {
    kasumi::transport::Transport result;
    result.state = {&state, destroy_fake};
    result.storage = {
        .initialize = fake_initialize,
        .put = fake_put,
        .get = fake_get,
        .presence = fake_presence,
        .list = fake_list,
        .list_prefix = fake_list_prefix,
        .remove = fake_remove,
    };
    return result;
}

struct FakeStorage {
    TempWorkspace workspace;
    std::unique_ptr<FakeState> state;
    kasumi::transport::Transport transport;
};

FakeStorage make_fake_storage() {
    FakeStorage storage{.workspace = kasumi::test::make_temp_workspace(
                            "observation-history-fake"),
                        .state = std::make_unique<FakeState>(),
                        .transport = {}};
    storage.transport = make_fake_transport(*storage.state);
    return storage;
}

kasumi::application::history_storage::PublishedCommit
publish(LocalStorage& storage, const Commit& commit) {
    auto result = kasumi::application::history_storage::publish_commit(
        storage.transport,
        test_key(),
        commit,
        kasumi::test::workspace_root(storage.workspace));
    EXPECT_TRUE(result.has_value());
    return result ? *result
                  : kasumi::application::history_storage::PublishedCommit{};
}

kasumi::application::history_storage::PublishedCommit
publish(FakeStorage& storage, const Commit& commit) {
    auto result = kasumi::application::history_storage::publish_commit(
        storage.transport,
        test_key(),
        commit,
        kasumi::test::workspace_root(storage.workspace));
    EXPECT_TRUE(result.has_value());
    return result ? *result
                  : kasumi::application::history_storage::PublishedCommit{};
}

std::expected<StorageView, kasumi::application::observation::history::Error>
observe(FakeStorage& storage,
        bool audit = false,
        const kasumi::application::history_storage::KnownHistoryAnchor* anchor =
            nullptr,
        const kasumi::application::history_storage::epoch::Reference*
            accepted_epoch = nullptr,
        std::span<const std::string> trusted_marker_identifiers = {}) {
    std::optional<kasumi::application::history_storage::KnownHistoryFrontier>
        frontier;
    if (anchor != nullptr || accepted_epoch != nullptr) {
        frontier.emplace();
        if (anchor != nullptr) {
            frontier->anchors.push_back(*anchor);
        }
        if (accepted_epoch != nullptr) {
            frontier->accepted_epoch = *accepted_epoch;
        }
    }
    return kasumi::application::observation::history::observe(
        storage.transport,
        test_key(),
        kasumi::test::workspace_root(storage.workspace),
        audit,
        frontier ? &*frontier : nullptr,
        trusted_marker_identifiers);
}

std::expected<StorageView, kasumi::application::observation::history::Error>
observe(LocalStorage& storage, bool audit = false, Key key = test_key()) {
    return kasumi::application::observation::history::observe(
        storage.transport,
        key,
        kasumi::test::workspace_root(storage.workspace),
        audit);
}

kasumi::application::history_storage::HeadReference
add_unmarked_variant(LocalStorage& storage, const Commit& commit) {
    const auto canonical = kasumi::history::serialize(commit).value();
    const auto plaintext =
        kasumi::test::workspace_path(storage.workspace, "orphan.kcom");
    const auto ciphertext =
        kasumi::test::workspace_path(storage.workspace, "orphan.ciphertext");
    kasumi::test::write_binary(plaintext, std::as_bytes(std::span{canonical}));
    EXPECT_TRUE(
        kasumi::crypto::encrypt_file(plaintext,
                                     ciphertext,
                                     test_key(),
                                     kasumi::crypto::FilePurpose::History));
    const auto hash = kasumi::crypto::content::hash_file(ciphertext).value();
    kasumi::application::history_storage::HeadReference reference{
        .commit_id = commit_id(commit),
        .ciphertext_id = kasumi::hash_hex(hash),
    };
    EXPECT_TRUE(kasumi::transport::put(
        storage.transport, ciphertext, object_path(reference)));
    return reference;
}

void add_marked_variant(LocalStorage& storage, const Commit& commit) {
    const auto reference = add_unmarked_variant(storage, commit);
    const auto marker =
        kasumi::application::history_storage::encode_marker(reference).value();
    const auto marker_file =
        kasumi::test::workspace_path(storage.workspace, "variant.head");
    kasumi::test::write_binary(marker_file, std::as_bytes(std::span{marker}));
    EXPECT_TRUE(kasumi::transport::put(
        storage.transport, marker_file, marker_path(reference)));
}

kasumi::application::history_storage::epoch::SealedEpoch
publish_epoch(FakeStorage& storage,
              const kasumi::application::history_storage::epoch::Epoch& epoch) {
    auto sealed =
        kasumi::application::history_storage::epoch::seal(epoch, test_key());
    EXPECT_TRUE(sealed.has_value());
    if (sealed) {
        EXPECT_TRUE(kasumi::application::history_storage::epoch::publish(
            storage.transport,
            *sealed,
            kasumi::test::workspace_root(storage.workspace)));
        return *sealed;
    }
    return {};
}

TEST(HistoryObservationTest, EmptyHistoryIgnoresOrphanCommits) {
    auto storage = make_local_storage();
    auto empty = observe(storage);
    ASSERT_TRUE(empty.has_value());
    EXPECT_FALSE(empty->history_present);
    EXPECT_TRUE(empty->effective_tree.rows.empty());
    EXPECT_TRUE(empty->marked_heads.empty());
    EXPECT_TRUE(empty->logical_heads.empty());
    EXPECT_TRUE(empty->ancestral_marked_heads.empty());

    const auto orphan = make_commit(0, {}, make_tree({{"orphan.txt", "x"}}));
    add_unmarked_variant(storage, orphan);
    auto still_empty = observe(storage);
    ASSERT_TRUE(still_empty.has_value());
    EXPECT_FALSE(still_empty->history_present);
}

TEST(HistoryObservationTest,
     BrokenEpochChainFailsBeforeObservationSideEffects) {
    auto storage = make_local_storage();
    const auto commit = make_commit(0, {}, make_tree({{"file.txt", "one"}}));
    publish(storage, commit);

    const auto vault_id = std::string(64, 'a');
    const auto genesis = kasumi::application::history_storage::epoch::seal(
        {.vault_id = vault_id,
         .sequence = 0,
         .issued_at = 100,
         .policy = {},
         .anchors = {{.commit_id = commit_id(commit), .height = 0}},
         .previous_epoch_id = {}},
        test_key());
    ASSERT_TRUE(genesis.has_value());
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        storage.transport,
        *genesis,
        kasumi::test::workspace_root(storage.workspace)));

    const auto broken = kasumi::application::history_storage::epoch::seal(
        {.vault_id = vault_id,
         .sequence = 1,
         .issued_at = 101,
         .policy = {},
         .anchors = {{.commit_id = commit_id(commit), .height = 0}},
         .previous_epoch_id = std::string(64, 'f')},
        test_key());
    ASSERT_TRUE(broken.has_value());
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        storage.transport,
        *broken,
        kasumi::test::workspace_root(storage.workspace)));

    const auto before = kasumi::transport::list(storage.transport);
    ASSERT_TRUE(before.has_value());
    const auto observed = observe(storage);
    ASSERT_FALSE(observed.has_value());
    EXPECT_EQ(observed.error().code, ErrorCode::HistoryStorageFailure);
    const auto after = kasumi::transport::list(storage.transport);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*after, *before);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(storage.workspace)));
}

TEST(HistoryObservationTest, SingleHeadIsEffectiveAndPublishable) {
    auto storage = make_local_storage();
    const auto commit = make_commit(0, {}, make_tree({{"file.txt", "one"}}));
    publish(storage, commit);

    auto view = observe(storage);
    ASSERT_TRUE(view.has_value());
    EXPECT_TRUE(view->history_present);
    EXPECT_EQ(view->observed_height, 0);
    ASSERT_EQ(view->marked_heads.size(), 1);
    EXPECT_EQ(view->marked_heads, view->logical_heads);
    EXPECT_TRUE(view->ancestral_marked_heads.empty());
    EXPECT_FALSE(view->has_conflicts);
    EXPECT_TRUE(same_tree(view->effective_tree, commit.tree));

    auto convergence = kasumi::history::make_commit(
        view->observed_height + 1, view->logical_heads, view->effective_tree);
    EXPECT_TRUE(convergence.has_value());
}

TEST(HistoryObservationTest, ReportsAncestralMarkedHeadsWithoutDeletingThem) {
    auto storage = make_local_storage();
    Commit previous = make_commit(0, {}, make_tree({{"file.txt", "a"}}));
    std::vector<std::string> ids;
    for (std::uint64_t height = 0; height < 4; ++height) {
        if (height != 0) {
            previous =
                make_commit(height,
                            {commit_id(previous)},
                            make_tree({{"file.txt", std::to_string(height)}}));
        }
        ids.push_back(commit_id(previous));
        publish(storage, previous);
    }
    const auto before = kasumi::transport::list(storage.transport).value();

    auto view = observe(storage);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->marked_heads.size(), 4);
    ASSERT_EQ(view->logical_heads.size(), 1);
    EXPECT_EQ(view->logical_heads.front(), ids.back());
    EXPECT_EQ(view->ancestral_marked_heads.size(), 3);
    EXPECT_TRUE(std::ranges::includes(view->marked_heads,
                                      view->ancestral_marked_heads));
    const auto after = kasumi::transport::list(storage.transport).value();
    EXPECT_EQ(before, after);
}

TEST(HistoryObservationTest, AcceptsSixtyFourMarkedCommitsInAChain) {
    auto storage = make_local_storage();
    Commit previous = make_commit(0, {}, make_tree({{"file.txt", "0"}}));
    for (std::uint64_t height = 0; height < 64; ++height) {
        if (height != 0) {
            previous =
                make_commit(height,
                            {commit_id(previous)},
                            make_tree({{"file.txt", std::to_string(height)}}));
        }
        publish(storage, previous);
    }

    auto view = observe(storage);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->marked_heads.size(), 64);
    EXPECT_EQ(view->logical_heads.size(), 1);
    EXPECT_EQ(view->ancestral_marked_heads.size(), 63);
}

TEST(HistoryObservationTest, MergesIndependentHeads) {
    auto storage = make_local_storage();
    const auto base = make_commit(0, {}, make_tree({}));
    const auto base_id = commit_id(base);
    publish(storage, base);
    const auto left = make_commit(1, {base_id}, make_tree({{"left.txt", "l"}}));
    const auto right =
        make_commit(1, {base_id}, make_tree({{"right.txt", "r"}}));
    publish(storage, left);
    publish(storage, right);

    auto view = observe(storage);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->logical_heads.size(), 2);
    EXPECT_TRUE(kasumi::find_row(view->effective_tree, "left.txt"));
    EXPECT_TRUE(kasumi::find_row(view->effective_tree, "right.txt"));
    EXPECT_FALSE(view->has_conflicts);
    EXPECT_EQ(view->observed_height, 1);
}

TEST(HistoryObservationTest, PreservesDeterministicConflicts) {
    auto storage = make_local_storage();
    const auto base = make_commit(0, {}, make_tree({{"same.txt", "base"}}));
    const auto base_id = commit_id(base);
    publish(storage, base);
    publish(storage,
            make_commit(1, {base_id}, make_tree({{"same.txt", "left"}})));
    publish(storage,
            make_commit(1, {base_id}, make_tree({{"same.txt", "right"}})));

    auto first = observe(storage);
    auto second = observe(storage);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_TRUE(first->has_conflicts);
    EXPECT_TRUE(same_tree(first->effective_tree, second->effective_tree));
    EXPECT_TRUE(
        std::ranges::any_of(first->effective_tree.rows, [](const auto& row) {
            return row.path.find(".kasumiconflict_") != std::string::npos;
        }));
}

TEST(HistoryObservationTest, DoesNotTreatCiphertextVariantsAsHeads) {
    auto storage = make_local_storage();
    const auto commit = make_commit(0, {}, make_tree({{"file.txt", "one"}}));
    publish(storage, commit);
    add_marked_variant(storage, commit);

    auto view = observe(storage);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->marked_heads.size(), 1);
    EXPECT_EQ(view->logical_heads.size(), 1);
    EXPECT_TRUE(view->ancestral_marked_heads.empty());
}

TEST(HistoryObservationTest, RejectsAmbiguousCrissCrossMerge) {
    auto storage = make_local_storage();
    const auto base = make_commit(0, {}, make_tree({}));
    const auto left =
        make_commit(1, {commit_id(base)}, make_tree({{"left.txt", "l"}}));
    const auto right =
        make_commit(1, {commit_id(base)}, make_tree({{"right.txt", "r"}}));
    const auto left_id = commit_id(left);
    const auto right_id = commit_id(right);
    auto merge_parents = std::vector<std::string>{left_id, right_id};
    std::ranges::sort(merge_parents);
    publish(storage, base);
    publish(storage, left);
    publish(storage, right);
    publish(storage,
            make_commit(2,
                        merge_parents,
                        make_tree({{"left.txt", "l"}, {"right.txt", "r"}})));
    publish(
        storage,
        make_commit(2,
                    merge_parents,
                    make_tree({{"left.txt", "other"}, {"right.txt", "r"}})));

    auto view = observe(storage);
    ASSERT_FALSE(view.has_value());
    EXPECT_EQ(view.error().code, ErrorCode::ResolutionFailure);
    EXPECT_NE(view.error().detail.find("ambiguous"), std::string::npos);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(storage.workspace)));
}

TEST(HistoryObservationTest, RejectsMoreThanThirtyTwoLogicalHeads) {
    auto storage = make_local_storage();
    const auto base = make_commit(0, {}, make_tree({}));
    const auto base_id = commit_id(base);
    publish(storage, base);
    for (std::size_t index = 0; index < 33; ++index) {
        publish(
            storage,
            make_commit(1,
                        {base_id},
                        make_tree({{"file-" + std::to_string(index), "x"}})));
    }

    auto view = observe(storage);
    ASSERT_FALSE(view.has_value());
    EXPECT_EQ(view.error().code, ErrorCode::LimitExceeded);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(storage.workspace)));
}

TEST(HistoryObservationTest, AuditsOnlyCanonicalRootContentIdentifiers) {
    auto storage = make_local_storage();
    const auto content =
        kasumi::test::workspace_path(storage.workspace, "content");
    kasumi::test::write_text(content, "content");
    const auto content_hash = kasumi::hasher::hash_string("content");
    const auto content_id =
        kasumi::crypto::content_identifier(test_key(), content_hash);

    EXPECT_TRUE(kasumi::transport::put(storage.transport, content, content_id));
    EXPECT_TRUE(
        kasumi::transport::put(storage.transport, content, "A" + content_id));
    EXPECT_TRUE(
        kasumi::transport::put(storage.transport, content, "history/unknown"));
    EXPECT_TRUE(
        kasumi::transport::put(storage.transport, content, "foreign/object"));

    const auto commit =
        make_commit(0, {}, make_tree({{"file.txt", "content"}}));
    publish(storage, commit);

    auto audited = observe(storage, true);
    ASSERT_TRUE(audited.has_value());
    EXPECT_EQ(audited->content_identifiers,
              std::unordered_set<std::string>{kasumi::hash_hex(content_hash)});
    EXPECT_EQ(audited->content_object_identifiers,
              std::vector<std::string>{content_id});

    auto not_audited = observe(storage, false);
    ASSERT_TRUE(not_audited.has_value());
    EXPECT_TRUE(not_audited->content_identifiers.empty());
    EXPECT_TRUE(not_audited->content_object_identifiers.empty());
}

TEST(HistoryObservationTest, ClassifiesWorkspaceRoots) {
    auto storage = make_local_storage();

    auto empty = kasumi::application::observation::history::observe(
        storage.transport, test_key(), {}, false);
    ASSERT_FALSE(empty.has_value());
    EXPECT_EQ(empty.error().code, ErrorCode::InvalidInput);

    auto missing = kasumi::application::observation::history::observe(
        storage.transport,
        test_key(),
        kasumi::test::workspace_path(storage.workspace, "missing"),
        false);
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code, ErrorCode::WorkspaceFailure);
    EXPECT_NE(missing.error().detail.find("não existe"), std::string::npos);

    const auto file =
        kasumi::test::workspace_path(storage.workspace, "workspace-file");
    kasumi::test::write_text(file, "not a directory");
    auto regular_file = kasumi::application::observation::history::observe(
        storage.transport, test_key(), file, false);
    ASSERT_FALSE(regular_file.has_value());
    EXPECT_EQ(regular_file.error().code, ErrorCode::WorkspaceFailure);

    const auto target =
        kasumi::test::workspace_path(storage.workspace, "workspace-target");
    std::error_code error;
    std::filesystem::create_directory(target, error);
    ASSERT_FALSE(error);
    const auto link =
        kasumi::test::workspace_path(storage.workspace, "workspace-link");
    std::filesystem::create_directory_symlink(target, link, error);
    if (error) {
        GTEST_SKIP() << "symlink unavailable: " << error.message();
    }
    auto symlink = kasumi::application::observation::history::observe(
        storage.transport, test_key(), link, false);
    ASSERT_FALSE(symlink.has_value());
    EXPECT_EQ(symlink.error().code, ErrorCode::WorkspaceFailure);
    EXPECT_NE(symlink.error().detail.find("link simbólico"), std::string::npos);
}

TEST(HistoryObservationTest, PreservesHistoryStorageWorkspaceFailure) {
    auto storage = make_fake_storage();
    publish(storage, make_commit(0, {}, make_tree({{"file.txt", "one"}})));
    storage.state->directory_destination = true;

    auto result = observe(storage);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::WorkspaceFailure);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(storage.workspace)));
}

TEST(HistoryObservationTest, MapsFirstListFailureToTransportFailure) {
    auto storage = make_fake_storage();
    storage.state->fail_first_list = true;

    auto result = observe(storage);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::TransportFailure);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(storage.workspace)));
    EXPECT_EQ(storage.state->put_count, 0);
    EXPECT_EQ(storage.state->remove_count, 0);
}

TEST(HistoryObservationTest, MapsMarkerAndCommitGetFailuresToTransportFailure) {
    auto marker_storage = make_fake_storage();
    publish(marker_storage,
            make_commit(0, {}, make_tree({{"file.txt", "marker"}})));
    marker_storage.state->fail_marker_get = true;
    auto marker = observe(marker_storage);
    ASSERT_FALSE(marker.has_value());
    EXPECT_EQ(marker.error().code, ErrorCode::TransportFailure);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(marker_storage.workspace)));

    auto commit_storage = make_fake_storage();
    publish(commit_storage,
            make_commit(0, {}, make_tree({{"file.txt", "commit"}})));
    commit_storage.state->fail_commit_get = true;
    auto commit = observe(commit_storage);
    ASSERT_FALSE(commit.has_value());
    EXPECT_EQ(commit.error().code, ErrorCode::TransportFailure);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(commit_storage.workspace)));
}

TEST(HistoryObservationTest, AuditedObservationNeverRequestsASecondListing) {
    auto storage = make_fake_storage();
    publish(storage, make_commit(0, {}, make_tree({{"file.txt", "one"}})));
    storage.state->list_count = 0;
    storage.state->fail_second_list = true;

    auto audited = observe(storage, true);
    ASSERT_TRUE(audited.has_value());
    EXPECT_EQ(storage.state->list_count, 1);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(storage.workspace)));

    storage.state->list_count = 0;
    storage.state->fail_second_list = false;
    auto not_audited = observe(storage, false);
    ASSERT_TRUE(not_audited.has_value());
    EXPECT_EQ(storage.state->list_count, 2);
}

TEST(HistoryObservationTest, ScopedNoOpIgnoresIrrelevantObjectCount) {
    auto storage = make_fake_storage();
    const auto current = make_commit(0, {}, make_tree({{"file.txt", "one"}}));
    publish(storage, current);
    for (std::size_t index = 0; index < 10'000; ++index) {
        storage.state->objects["irrelevant/" + std::to_string(index)] = {0};
    }
    storage.state->list_count = 0;
    storage.state->full_list_count = 0;
    storage.state->prefix_list_count = 0;
    storage.state->marker_get_count = 0;
    storage.state->commit_get_count = 0;
    const kasumi::application::history_storage::KnownHistoryAnchor anchor{
        .commit_id = commit_id(current),
        .height = current.height,
        .tree = current.tree,
    };

    auto observed = observe(storage, false, &anchor);
    ASSERT_TRUE(observed.has_value());
    EXPECT_EQ(storage.state->full_list_count, 0U);
    EXPECT_EQ(storage.state->prefix_list_count, 2U);
    EXPECT_EQ(storage.state->marker_get_count, 1U);
    EXPECT_EQ(storage.state->commit_get_count, 0U);
}

TEST(HistoryObservationTest, AuditingReusesTheHistoryListing) {
    auto storage = make_fake_storage();
    publish(storage, make_commit(0, {}, make_tree({{"file.txt", "one"}})));
    storage.state->list_count = 0;
    storage.state->put_count = 0;
    storage.state->remove_count = 0;

    auto not_audited = observe(storage, false);
    ASSERT_TRUE(not_audited.has_value());
    EXPECT_EQ(storage.state->list_count, 2);

    storage.state->list_count = 0;
    auto audited = observe(storage, true);
    ASSERT_TRUE(audited.has_value());
    EXPECT_EQ(storage.state->list_count, 1);
    EXPECT_EQ(storage.state->put_count, 0);
    EXPECT_EQ(storage.state->remove_count, 0);
}

TEST(HistoryObservationTest, AuditHelperDeduplicatesAndEnforcesLimit) {
    const std::vector<std::string> hashes{
        kasumi::hash_hex(kasumi::hasher::hash_string("one")),
        kasumi::hash_hex(kasumi::hasher::hash_string("two")),
        kasumi::hash_hex(kasumi::hasher::hash_string("three")),
    };
    const std::vector<std::string> within_limit{
        hashes[0], hashes[1], hashes[2], hashes[0], "not-an-object"};
    auto accepted = kasumi::application::observation::history::detail::
        collect_content_identifiers(within_limit, 3);
    ASSERT_TRUE(accepted.has_value());
    EXPECT_EQ(accepted->size(), 3);

    const std::vector<std::string> over_limit{
        hashes[0],
        hashes[1],
        hashes[2],
        kasumi::hash_hex(kasumi::hasher::hash_string("four"))};
    auto rejected = kasumi::application::observation::history::detail::
        collect_content_identifiers(over_limit, 3);
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code, ErrorCode::LimitExceeded);
}

TEST(HistoryObservationTest, MarkerCorruptionMapsToStorageFailure) {
    auto storage = make_local_storage();
    const auto published =
        publish(storage, make_commit(0, {}, make_tree({{"file.txt", "one"}})));
    kasumi::test::write_text(
        kasumi::test::workspace_path(storage.workspace, "storage") /
            std::filesystem::path{marker_path(published.head)},
        "corrupt marker");

    auto result = observe(storage);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::HistoryStorageFailure);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(storage.workspace)));
}

TEST(HistoryObservationTest, ObservationIsReadOnlyAndListingOrderIndependent) {
    auto storage = make_fake_storage();
    const auto base = make_commit(0, {}, make_tree({}));
    const auto base_id = commit_id(base);
    publish(storage, base);
    publish(storage,
            make_commit(1, {base_id}, make_tree({{"same.txt", "left"}})));
    publish(storage,
            make_commit(1, {base_id}, make_tree({{"same.txt", "right"}})));

    storage.state->list_count = 0;
    storage.state->put_count = 0;
    storage.state->remove_count = 0;
    auto normal = observe(storage);
    ASSERT_TRUE(normal.has_value());
    EXPECT_EQ(normal->marked_heads.size(), 3);
    EXPECT_TRUE(normal->has_conflicts);
    EXPECT_EQ(storage.state->put_count, 0);
    EXPECT_EQ(storage.state->remove_count, 0);

    storage.state->reverse_listing = true;
    auto reversed = observe(storage);
    ASSERT_TRUE(reversed.has_value());
    EXPECT_TRUE(same_tree(normal->effective_tree, reversed->effective_tree));
    EXPECT_EQ(normal->observed_height, reversed->observed_height);
    EXPECT_EQ(normal->marked_heads, reversed->marked_heads);
    EXPECT_EQ(normal->logical_heads, reversed->logical_heads);
    EXPECT_EQ(normal->ancestral_marked_heads, reversed->ancestral_marked_heads);
    EXPECT_EQ(normal->content_identifiers, reversed->content_identifiers);
    EXPECT_EQ(normal->history_present, reversed->history_present);
    EXPECT_EQ(normal->has_conflicts, reversed->has_conflicts);
    EXPECT_EQ(storage.state->list_count, 4);
    EXPECT_EQ(storage.state->put_count, 0);
    EXPECT_EQ(storage.state->remove_count, 0);
}

TEST(HistoryObservationTest, MapsWrongKeyAndCorruptionToStorageFailure) {
    auto storage = make_local_storage();
    const auto commit = make_commit(0, {}, make_tree({{"file.txt", "one"}}));
    const auto published = publish(storage, commit);

    auto wrong_key = test_key();
    wrong_key[0] ^= 0xffU;
    auto wrong = observe(storage, false, wrong_key);
    ASSERT_FALSE(wrong.has_value());
    EXPECT_EQ(wrong.error().code, ErrorCode::HistoryStorageFailure);

    kasumi::test::write_text(
        kasumi::test::workspace_path(storage.workspace, "storage") /
            std::filesystem::path{object_path(published.head)},
        "corrupt");
    auto corrupt = observe(storage);
    ASSERT_FALSE(corrupt.has_value());
    EXPECT_EQ(corrupt.error().code, ErrorCode::HistoryStorageFailure);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(storage.workspace)));
}

TEST(HistoryObservationTest, LeavesHistoryWorkspaceClean) {
    auto storage = make_local_storage();
    publish(storage, make_commit(0, {}, make_tree({{"file.txt", "one"}})));
    ASSERT_TRUE(observe(storage).has_value());
    for (const auto& entry : std::filesystem::directory_iterator(
             kasumi::test::workspace_root(storage.workspace))) {
        EXPECT_FALSE(
            entry.path().filename().string().starts_with(".kasumi-history-"));
    }
}

TEST(HistoryObservationTest, AnchoredNoOpCommitGetsStayZeroAcrossHistoryDepth) {
    for (const std::uint64_t depth : {1ULL, 10ULL, 50ULL, 100ULL}) {
        SCOPED_TRACE(depth);
        auto storage = make_fake_storage();
        Commit current = make_commit(0, {}, make_tree({{"file.txt", "0"}}));
        auto published = publish(storage, current);
        for (std::uint64_t height = 1; height < depth; ++height) {
            const auto previous = published.head;
            current =
                make_commit(height,
                            {commit_id(current)},
                            make_tree({{"file.txt", std::to_string(height)}}));
            published = publish(storage, current);
            storage.state->objects.erase(marker_path(previous));
        }

        storage.state->list_count = 0;
        storage.state->full_list_count = 0;
        storage.state->prefix_list_count = 0;
        storage.state->get_count = 0;
        storage.state->marker_get_count = 0;
        storage.state->commit_get_count = 0;
        const kasumi::application::history_storage::KnownHistoryAnchor anchor{
            .commit_id = commit_id(current),
            .height = current.height,
            .tree = current.tree,
        };

        auto observed = observe(storage, false, &anchor);
        ASSERT_TRUE(observed.has_value());
        EXPECT_EQ(storage.state->list_count, 2);
        EXPECT_EQ(storage.state->full_list_count, 0);
        EXPECT_EQ(storage.state->prefix_list_count, 2);
        EXPECT_EQ(storage.state->marker_get_count, 1);
        EXPECT_EQ(storage.state->commit_get_count, 0);
        EXPECT_TRUE(same_tree(observed->effective_tree, current.tree));
    }
}

TEST(
    HistoryObservationTest,
    AnchoredNoOpWithUnchangedAcceptedEpochKeepsCommitGetsZeroAcrossHistoryDepth) {
    for (const std::uint64_t depth : {1ULL, 10ULL, 50ULL, 100ULL}) {
        SCOPED_TRACE(depth);
        auto storage = make_fake_storage();
        Commit current = make_commit(0, {}, make_tree({{"file.txt", "0"}}));
        auto published = publish(storage, current);
        const auto epoch = publish_epoch(
            storage,
            {.vault_id = std::string(64, 'a'),
             .sequence = 0,
             .issued_at = 100,
             .policy = {},
             .anchors = {{.commit_id = commit_id(current), .height = 0}},
             .previous_epoch_id = {}});
        for (std::uint64_t height = 1; height < depth; ++height) {
            const auto previous = published.head;
            current =
                make_commit(height,
                            {commit_id(current)},
                            make_tree({{"file.txt", std::to_string(height)}}));
            published = publish(storage, current);
            storage.state->objects.erase(marker_path(previous));
        }

        storage.state->commit_get_count = 0;
        const kasumi::application::history_storage::KnownHistoryAnchor anchor{
            .commit_id = commit_id(current),
            .height = current.height,
            .tree = current.tree,
        };
        const std::array trusted_markers{marker_path(published.head)};

        const kasumi::application::history_storage::KnownHistoryFrontier
            frontier{.anchors = {anchor}, .accepted_epoch = epoch.reference};
        auto loaded = kasumi::application::history_storage::load_history_scoped(
            storage.transport,
            test_key(),
            kasumi::test::workspace_root(storage.workspace),
            &frontier,
            trusted_markers);
        ASSERT_TRUE(loaded.has_value());
        EXPECT_EQ(loaded->trusted_anchor_ids,
                  std::vector<std::string>{anchor.commit_id});
        ASSERT_TRUE(loaded->epoch.has_value());
        EXPECT_EQ(loaded->epoch->reference, epoch.reference);
        EXPECT_EQ(storage.state->commit_get_count, 0);
        storage.state->commit_get_count = 0;

        auto observed =
            observe(storage, false, &anchor, &epoch.reference, trusted_markers);
        ASSERT_TRUE(observed.has_value());
        ASSERT_TRUE(observed->epoch.has_value());
        EXPECT_EQ(observed->epoch->reference, epoch.reference);
        EXPECT_EQ(storage.state->commit_get_count, 0);
        EXPECT_TRUE(same_tree(observed->effective_tree, current.tree));
    }
}

TEST(HistoryObservationTest,
     AnchoredObservationWithUnchangedAcceptedEpochLoadsOnlyNewCommits) {
    for (const std::uint64_t delta : {1ULL, 3ULL}) {
        SCOPED_TRACE(delta);
        auto storage = make_fake_storage();
        Commit current = make_commit(0, {}, make_tree({{"file.txt", "0"}}));
        auto published = publish(storage, current);
        const auto epoch = publish_epoch(
            storage,
            {.vault_id = std::string(64, 'a'),
             .sequence = 0,
             .issued_at = 100,
             .policy = {},
             .anchors = {{.commit_id = commit_id(current), .height = 0}},
             .previous_epoch_id = {}});
        Commit cached = current;
        for (std::uint64_t height = 1; height <= 10 + delta; ++height) {
            const auto previous = published.head;
            current =
                make_commit(height,
                            {commit_id(current)},
                            make_tree({{"file.txt", std::to_string(height)}}));
            published = publish(storage, current);
            storage.state->objects.erase(marker_path(previous));
            if (height == 10) {
                cached = current;
            }
        }

        storage.state->commit_get_count = 0;
        const kasumi::application::history_storage::KnownHistoryAnchor anchor{
            .commit_id = commit_id(cached),
            .height = cached.height,
            .tree = cached.tree,
        };
        const std::array trusted_markers{marker_path(published.head)};

        auto observed =
            observe(storage, false, &anchor, &epoch.reference, trusted_markers);
        ASSERT_TRUE(observed.has_value());
        ASSERT_TRUE(observed->epoch.has_value());
        EXPECT_EQ(observed->epoch->reference, epoch.reference);
        EXPECT_EQ(storage.state->commit_get_count, delta);
        EXPECT_TRUE(same_tree(observed->effective_tree, current.tree));
    }
}

TEST(HistoryObservationTest, AdvancedEpochDisablesCachedAnchorShortcut) {
    auto storage = make_fake_storage();
    const auto base = make_commit(0, {}, make_tree({{"file.txt", "base"}}));
    const auto base_published = publish(storage, base);
    const auto accepted =
        publish_epoch(storage,
                      {.vault_id = std::string(64, 'a'),
                       .sequence = 0,
                       .issued_at = 100,
                       .policy = {},
                       .anchors = {{.commit_id = commit_id(base), .height = 0}},
                       .previous_epoch_id = {}});
    const auto cached =
        make_commit(1, {commit_id(base)}, make_tree({{"cached.txt", "a"}}));
    const auto remote =
        make_commit(1, {commit_id(base)}, make_tree({{"remote.txt", "b"}}));
    const auto remote_published = publish(storage, remote);
    storage.state->objects.erase(marker_path(base_published.head));
    const auto latest = publish_epoch(
        storage,
        {.vault_id = std::string(64, 'a'),
         .sequence = 1,
         .issued_at = 101,
         .policy = {},
         .anchors = {{.commit_id = commit_id(remote), .height = 1}},
         .previous_epoch_id = accepted.reference.epoch_id});
    storage.state->commit_get_count = 0;
    const kasumi::application::history_storage::KnownHistoryAnchor anchor{
        .commit_id = commit_id(cached),
        .height = cached.height,
        .tree = cached.tree,
    };
    const std::array trusted_markers{marker_path(remote_published.head)};

    auto observed =
        observe(storage, false, &anchor, &accepted.reference, trusted_markers);
    ASSERT_TRUE(observed.has_value());
    ASSERT_TRUE(observed->epoch.has_value());
    EXPECT_EQ(observed->epoch->reference, latest.reference);
    EXPECT_EQ(storage.state->commit_get_count, 1);
    EXPECT_TRUE(same_tree(observed->effective_tree, remote.tree));
}

TEST(HistoryObservationTest,
     UnchangedEpochFallsBackWhenRemoteBranchMissesCachedAnchor) {
    auto storage = make_fake_storage();
    const auto base = make_commit(0, {}, make_tree({{"file.txt", "base"}}));
    const auto base_published = publish(storage, base);
    const auto epoch =
        publish_epoch(storage,
                      {.vault_id = std::string(64, 'a'),
                       .sequence = 0,
                       .issued_at = 100,
                       .policy = {},
                       .anchors = {{.commit_id = commit_id(base), .height = 0}},
                       .previous_epoch_id = {}});
    const auto cached =
        make_commit(1, {commit_id(base)}, make_tree({{"cached.txt", "a"}}));
    const auto cached_published = publish(storage, cached);
    const auto remote =
        make_commit(1, {commit_id(base)}, make_tree({{"remote.txt", "b"}}));
    const auto remote_published = publish(storage, remote);
    storage.state->objects.erase(marker_path(base_published.head));
    storage.state->objects.erase(marker_path(cached_published.head));
    storage.state->commit_get_count = 0;
    const kasumi::application::history_storage::KnownHistoryAnchor anchor{
        .commit_id = commit_id(cached),
        .height = cached.height,
        .tree = cached.tree,
    };
    const std::array trusted_markers{marker_path(remote_published.head)};

    auto observed =
        observe(storage, false, &anchor, &epoch.reference, trusted_markers);
    ASSERT_TRUE(observed.has_value());
    ASSERT_TRUE(observed->epoch.has_value());
    EXPECT_EQ(observed->epoch->reference, epoch.reference);
    EXPECT_EQ(storage.state->commit_get_count, 4);
    EXPECT_TRUE(same_tree(observed->effective_tree, remote.tree));
}

TEST(HistoryObservationTest, AnchoredObservationLoadsOnlyNewCommits) {
    auto storage = make_fake_storage();
    const auto base = make_commit(0, {}, make_tree({}));
    const auto base_published = publish(storage, base);
    const auto next =
        make_commit(1, {commit_id(base)}, make_tree({{"next.txt", "next"}}));
    publish(storage, next);
    storage.state->objects.erase(marker_path(base_published.head));
    storage.state->list_count = 0;
    storage.state->marker_get_count = 0;
    storage.state->commit_get_count = 0;
    const kasumi::application::history_storage::KnownHistoryAnchor anchor{
        .commit_id = commit_id(base), .height = 0, .tree = base.tree};

    auto observed = observe(storage, true, &anchor);
    ASSERT_TRUE(observed.has_value());
    EXPECT_EQ(storage.state->list_count, 1);
    EXPECT_EQ(storage.state->marker_get_count, 1);
    EXPECT_EQ(storage.state->commit_get_count, 1);
    EXPECT_EQ(observed->reachable_commits.size(), 2);
    EXPECT_TRUE(same_tree(observed->effective_tree, next.tree));
}

TEST(HistoryObservationTest, AnchoredMultiHeadLoadsOnlyBranchesAfterAnchor) {
    auto storage = make_fake_storage();
    const auto base = make_commit(0, {}, make_tree({}));
    const auto base_published = publish(storage, base);
    const auto left =
        make_commit(1, {commit_id(base)}, make_tree({{"left.txt", "left"}}));
    const auto right =
        make_commit(1, {commit_id(base)}, make_tree({{"right.txt", "right"}}));
    publish(storage, left);
    publish(storage, right);
    storage.state->objects.erase(marker_path(base_published.head));
    storage.state->marker_get_count = 0;
    storage.state->commit_get_count = 0;
    const kasumi::application::history_storage::KnownHistoryAnchor anchor{
        .commit_id = commit_id(base), .height = 0, .tree = base.tree};

    auto observed = observe(storage, true, &anchor);
    ASSERT_TRUE(observed.has_value());
    EXPECT_EQ(storage.state->marker_get_count, 2);
    EXPECT_EQ(storage.state->commit_get_count, 2);
    EXPECT_EQ(observed->logical_heads.size(), 2);
    EXPECT_TRUE(kasumi::find_row(observed->effective_tree, "left.txt"));
    EXPECT_TRUE(kasumi::find_row(observed->effective_tree, "right.txt"));
}

TEST(HistoryObservationTest, MissingAnchoredCommitFailsClosed) {
    auto storage = make_fake_storage();
    const auto commit =
        make_commit(0, {}, make_tree({{"file.txt", "contents"}}));
    const auto published = publish(storage, commit);
    storage.state->objects.erase(object_path(published.head));
    storage.state->marker_get_count = 0;
    storage.state->commit_get_count = 0;
    const kasumi::application::history_storage::KnownHistoryAnchor anchor{
        .commit_id = commit_id(commit),
        .height = 0,
        .tree = commit.tree,
    };

    auto observed = observe(storage, true, &anchor);
    ASSERT_FALSE(observed.has_value());
    EXPECT_EQ(observed.error().code, ErrorCode::HistoryStorageFailure);
    EXPECT_GT(storage.state->commit_get_count, 0);
}

TEST(HistoryObservationTest, AnchoredMarkerMustReferenceExistingVariant) {
    auto storage = make_fake_storage();
    const auto commit =
        make_commit(0, {}, make_tree({{"file.txt", "contents"}}));
    const auto published = publish(storage, commit);
    storage.state->objects.erase(object_path(published.head));
    const kasumi::application::history_storage::HeadReference unrelated{
        .commit_id = commit_id(commit), .ciphertext_id = std::string(64, 'f')};
    storage.state->objects[object_path(unrelated)] = {1, 2, 3};
    const kasumi::application::history_storage::KnownHistoryAnchor anchor{
        .commit_id = commit_id(commit),
        .height = 0,
        .tree = commit.tree,
    };

    auto observed = observe(storage, true, &anchor);

    ASSERT_FALSE(observed.has_value());
    EXPECT_EQ(observed.error().code, ErrorCode::HistoryStorageFailure);
}

TEST(HistoryObservationTest, MissingAnchoredMarkerFailsClosed) {
    auto storage = make_fake_storage();
    const auto commit =
        make_commit(0, {}, make_tree({{"file.txt", "contents"}}));
    const auto published = publish(storage, commit);
    storage.state->disappear_on_get = marker_path(published.head);
    const kasumi::application::history_storage::KnownHistoryAnchor anchor{
        .commit_id = commit_id(commit),
        .height = 0,
        .tree = commit.tree,
    };

    auto observed = observe(storage, true, &anchor);

    ASSERT_FALSE(observed.has_value());
    EXPECT_EQ(observed.error().code, ErrorCode::HistoryStorageFailure);
}

} // namespace
