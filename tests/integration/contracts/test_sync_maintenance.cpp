#include "application/execute.hpp"
#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/observation/history.hpp"
#include "application/profile.hpp"
#include "core/hasher.hpp"
#include "crypto/file_crypto.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "runtime/paths.hpp"
#include "runtime/vault.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

namespace {

using kasumi::application::Credentials;
using kasumi::application::ExecutionEnvironment;
using kasumi::application::MasterKeyHex;
using kasumi::application::NoCredentials;
using kasumi::application::Operation;
using kasumi::application::PlanReport;
using kasumi::application::Profile;
using kasumi::application::Request;
using kasumi::test::TempWorkspace;
namespace protocol = kasumi::application::history_storage::maintenance_protocol;

kasumi::application::ExecutionInput
request(Operation operation,
        const ExecutionEnvironment& environment,
        std::string profile = "demo") {
    return {Request{operation, std::move(profile)},
            Credentials{NoCredentials{}},
            environment};
}

std::string content_identifier(kasumi::transport::Transport& transport) {
    const auto identifiers = kasumi::transport::list(transport);
    if (!identifiers)
        return {};
    for (const auto& identifier : *identifiers) {
        if (kasumi::hash_from_hex(identifier).has_value())
            return identifier;
    }
    return {};
}

std::string canonical_orphan() {
    return kasumi::hash_hex(kasumi::hasher::hash_string("orphan"));
}

TEST(ApplicationMaintenanceContract,
     PublicSyncPreviewStatusFsckAndGcRemainAvailable) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-sync-maintenance");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{std::string(64, '7')}));
    kasumi::test::write_text(profile.local_dir / "file.txt", "one");
    const Credentials credentials{NoCredentials{}};

    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "remote").string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto initial_preview = kasumi::application::execute(
        {Request{Operation::Preview, "demo"}, credentials, environment});
    ASSERT_TRUE(initial_preview.has_value()) << initial_preview.error().detail;
    const auto& initial_plan = std::get<PlanReport>(initial_preview->data);
    EXPECT_EQ(initial_plan.action_counts[static_cast<std::size_t>(
                  kasumi::application::PlanAction::Upload)],
              1U);

    const auto first_sync = kasumi::application::execute(
        {Request{Operation::Sync, "demo"}, credentials, environment});
    if (!first_sync) {
        std::error_code error;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(
                 kasumi::test::workspace_path(workspace, "remote"), error)) {
            ADD_FAILURE() << entry.path().string();
        }
    }
    ASSERT_TRUE(first_sync.has_value()) << first_sync.error().detail;

    const auto status = kasumi::application::execute(
        {Request{Operation::Status, "demo"}, credentials, environment});
    ASSERT_TRUE(status.has_value());

    kasumi::test::write_text(profile.local_dir / "file.txt", "two");
    const auto preview = kasumi::application::execute(
        {Request{Operation::Preview, "demo"}, credentials, environment});
    ASSERT_TRUE(preview.has_value());
    ASSERT_TRUE(std::holds_alternative<PlanReport>(preview->data));
    EXPECT_EQ(kasumi::test::read_text(profile.local_dir / "file.txt"), "two");

    ASSERT_TRUE(kasumi::application::execute(
        {Request{Operation::Sync, "demo"}, credentials, environment}));
    ASSERT_TRUE(kasumi::application::execute(
        {Request{Operation::Sync, "demo"}, credentials, environment}));
    const auto key = kasumi::runtime::vault::decode_hex(std::string(64, '7'));
    ASSERT_TRUE(key.has_value());
    const auto history =
        kasumi::application::history_storage::inventory_reachability(
            storage, *key, environment.app_data_dir);
    ASSERT_TRUE(history.has_value());
    const auto content =
        kasumi::application::history_storage::inventory_content_reachability(
            storage, *key, *history, environment.app_data_dir);
    ASSERT_TRUE(content.has_value());
    ASSERT_EQ(history->valid_epochs.size(), 1U);
    EXPECT_TRUE(history->orphan_epochs.empty());
    EXPECT_TRUE(content->orphan_content_ids.empty());
    EXPECT_TRUE(history->orphan_commits.empty());

    for (const auto& commit : history->commits) {
        if (!commit.reachable) {
            continue;
        }
        const auto variant =
            std::ranges::find_if(commit.variants, [](const auto& value) {
                return value.state == kasumi::application::history_storage::
                                          detail::VariantState::Valid &&
                       !value.identifier.empty();
            });
        ASSERT_NE(variant, commit.variants.end());
        EXPECT_EQ(
            kasumi::transport::presence(storage, variant->identifier).value(),
            kasumi::transport::Presence::Present);
    }

    const auto fsck = kasumi::application::execute(
        {Request{Operation::Fsck, "demo"}, credentials, environment});
    ASSERT_TRUE(fsck.has_value());
    const auto gc = kasumi::application::execute(
        {Request{Operation::GarbageCollect, "demo"}, credentials, environment});
    ASSERT_TRUE(gc.has_value()) << gc.error().detail;
    ASSERT_TRUE(
        std::holds_alternative<kasumi::application::GarbageCollectCompleted>(
            gc->data));
    EXPECT_EQ(std::get<kasumi::application::GarbageCollectCompleted>(gc->data)
                  .quarantined_objects,
              0U);
    for (const auto& identifier : history->valid_epochs) {
        EXPECT_EQ(kasumi::transport::presence(storage, identifier).value(),
                  kasumi::transport::Presence::Present);
    }
    for (const auto& identifier : history->logical_heads) {
        const auto marker =
            std::ranges::find_if(history->markers, [&](const auto& value) {
                return value.reference &&
                       value.reference->commit_id == identifier &&
                       value.state == kasumi::application::history_storage::
                                          ReachabilityMarkerState::Valid;
            });
        ASSERT_NE(marker, history->markers.end());
        EXPECT_EQ(
            kasumi::transport::presence(storage, marker->identifier).value(),
            kasumi::transport::Presence::Present);
    }
    for (const auto& identifier : content->reachable_content_ids) {
        EXPECT_EQ(kasumi::transport::presence(storage, identifier).value(),
                  kasumi::transport::Presence::Present);
    }

    const auto post_gc_fsck = kasumi::application::execute(
        {Request{Operation::Fsck, "demo"}, credentials, environment});
    ASSERT_TRUE(post_gc_fsck.has_value()) << post_gc_fsck.error().detail;
}

TEST(ApplicationMaintenanceContract, UnknownObjectsArePreserved) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-unknown-objects");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{std::string(64, '6')}));
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "remote").string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto foreign =
        kasumi::test::workspace_path(workspace, "foreign-object");
    kasumi::test::write_text(foreign, "foreign");
    ASSERT_TRUE(kasumi::transport::put(storage, foreign, "foreign/object"));

    for (const auto operation :
         {Operation::Preview, Operation::Status, Operation::Sync}) {
        const auto result =
            kasumi::application::execute(request(operation, environment));
        ASSERT_TRUE(result.has_value()) << result.error().detail;
    }
    const auto fsck =
        kasumi::application::execute(request(Operation::Fsck, environment));
    ASSERT_FALSE(fsck.has_value());
    const auto identifiers = kasumi::transport::list(storage);
    ASSERT_TRUE(identifiers.has_value());
    EXPECT_TRUE(std::ranges::any_of(*identifiers, [](const auto& identifier) {
        return identifier.starts_with("history/commits/");
    }));
    EXPECT_TRUE(std::ranges::any_of(*identifiers, [](const auto& identifier) {
        return identifier.starts_with("history/heads/");
    }));
    EXPECT_EQ(kasumi::transport::presence(storage, "foreign/object").value(),
              kasumi::transport::Presence::Present);
}

TEST(ApplicationMaintenanceContract, StateOnlySyncCreatesOnlyLocalState) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-state-only");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    const MasterKeyHex key{std::string(64, '1')};
    ASSERT_TRUE(kasumi::application::create_profile(environment, profile, key));
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "file.txt", "same");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));

    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "remote").string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto before_listing = kasumi::transport::list(storage);
    ASSERT_TRUE(before_listing.has_value());
    const auto before_remote = kasumi::test::snapshot_tree(
        kasumi::test::workspace_path(workspace, "remote"));
    const auto decoded_key = kasumi::runtime::vault::decode_hex(key.value);
    ASSERT_TRUE(decoded_key.has_value());
    const auto observed = kasumi::application::observation::history::observe(
        storage, *decoded_key, environment.app_data_dir, false);
    ASSERT_TRUE(observed.has_value());
    ASSERT_EQ(observed->logical_heads.size(), 1U);
    const auto observed_commit =
        std::ranges::find(observed->reachable_commits,
                          observed->logical_heads.front(),
                          &kasumi::history::LoadedCommit::id);
    ASSERT_NE(observed_commit, observed->reachable_commits.end());
    const auto paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "demo");
    ASSERT_TRUE(paths.has_value());
    ASSERT_TRUE(std::filesystem::remove(paths->database_path));

    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));
    const auto after_listing = kasumi::transport::list(storage);
    ASSERT_TRUE(after_listing.has_value());
    EXPECT_EQ(*after_listing, *before_listing);
    EXPECT_EQ(kasumi::test::snapshot_tree(
                  kasumi::test::workspace_path(workspace, "remote")),
              before_remote);
    const auto stored = kasumi::state_storage::load_state(paths->database_path);
    ASSERT_TRUE(stored.has_value() && *stored);
    EXPECT_EQ((*stored)->commit_id, observed_commit->id);
    EXPECT_EQ((*stored)->height, observed_commit->commit.height);
    ASSERT_EQ((*stored)->tree.rows.size(),
              observed_commit->commit.tree.rows.size());
    for (std::size_t index = 0;
         index < observed_commit->commit.tree.rows.size();
         ++index) {
        const auto& expected = observed_commit->commit.tree.rows[index];
        const auto& actual = (*stored)->tree.rows[index];
        EXPECT_EQ(actual.path, expected.path);
        EXPECT_EQ(actual.hash, expected.hash);
        EXPECT_EQ(actual.size, expected.size);
        EXPECT_EQ(actual.mtime, expected.mtime);
        EXPECT_EQ(actual.is_directory, expected.is_directory);
    }
    ASSERT_NE(kasumi::find_row((*stored)->tree, "file.txt"), nullptr);
    EXPECT_FALSE(
        std::filesystem::exists(paths->profile_dir / "transaction.bin.enc"));
    const auto transactions = paths->profile_dir / ".transactions";
    if (std::filesystem::exists(transactions)) {
        EXPECT_TRUE(std::filesystem::is_empty(transactions));
    }
}

TEST(ApplicationMaintenanceContract,
     ReadOnlyOperationsDoNotCreateAnAbsentRemoteRoot) {
    auto workspace = kasumi::test::make_temp_workspace(
        "application-read-only-absent-remote");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{std::string(64, '2')}));
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    ASSERT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "remote")));

    for (const auto operation : {Operation::Preview, Operation::Status}) {
        const auto result =
            kasumi::application::execute(request(operation, environment));
        ASSERT_TRUE(result.has_value()) << result.error().detail;
        EXPECT_EQ(result->operation, operation);
        EXPECT_FALSE(std::filesystem::exists(
            kasumi::test::workspace_path(workspace, "remote")));
    }
}

TEST(ApplicationMaintenanceContract, NoOpSyncDoesNotRewriteStateOrRemote) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-sync-no-op");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{std::string(64, '3')}));
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "file.txt", "same");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));

    const auto paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "demo");
    ASSERT_TRUE(paths.has_value());
    const auto state_before = kasumi::test::read_binary(paths->database_path);
    const auto remote_before = kasumi::test::snapshot_tree(profile.remote_dir);
    auto opened = kasumi::transport::open_transport(profile.remote_dir);
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto listing_before = kasumi::transport::list(storage);
    ASSERT_TRUE(listing_before.has_value());

    const auto result =
        kasumi::application::execute(request(Operation::Sync, environment));
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->operation, Operation::Sync);
    EXPECT_EQ(kasumi::test::read_binary(paths->database_path), state_before);
    EXPECT_EQ(kasumi::test::snapshot_tree(profile.remote_dir), remote_before);
    const auto listing_after = kasumi::transport::list(storage);
    ASSERT_TRUE(listing_after.has_value());
    EXPECT_EQ(*listing_after, *listing_before);
    EXPECT_FALSE(
        std::filesystem::exists(paths->profile_dir / "transaction.bin.enc"));
}

TEST(ApplicationMaintenanceContract,
     StateOnlyRejectsAnUnreachableLogicalHeadWithoutCreatingState) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-state-only-unreachable");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{std::string(64, '4')}));
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "file.txt", "same");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));

    const auto paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "demo");
    ASSERT_TRUE(paths.has_value());
    ASSERT_TRUE(std::filesystem::remove(paths->database_path));
    auto opened = kasumi::transport::open_transport(profile.remote_dir);
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto listing = kasumi::transport::list(storage);
    ASSERT_TRUE(listing.has_value());
    auto commit = std::ranges::find_if(*listing, [](const auto& identifier) {
        return identifier.starts_with("history/commits/");
    });
    ASSERT_NE(commit, listing->end());
    ASSERT_EQ(kasumi::transport::remove(storage, *commit).value(),
              kasumi::transport::Removal::Removed);

    const auto result =
        kasumi::application::execute(request(Operation::Sync, environment));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, kasumi::application::ErrorCode::PlanFailure);
    EXPECT_FALSE(std::filesystem::exists(paths->database_path));
    EXPECT_FALSE(
        std::filesystem::exists(paths->profile_dir / "transaction.bin.enc"));
}

TEST(ApplicationMaintenanceContract, SyncBetweenTwoClientsIsIdempotent) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-two-clients");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const auto key = MasterKeyHex{std::string(64, '9')};
    const Profile first{"first",
                        kasumi::test::workspace_path(workspace, "first"),
                        remote.string()};
    const Profile second{"second",
                         kasumi::test::workspace_path(workspace, "second"),
                         remote.string()};
    ASSERT_TRUE(kasumi::application::create_profile(environment, first, key));
    ASSERT_TRUE(kasumi::application::create_profile(environment, second, key));
    ASSERT_TRUE(std::filesystem::create_directories(first.local_dir));
    ASSERT_TRUE(std::filesystem::create_directories(second.local_dir));
    auto opened = kasumi::transport::open_transport(remote.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(first.local_dir / "file.txt", "one");
    ASSERT_TRUE(kasumi::application::execute(
        request(Operation::Sync, environment, "first")));
    const auto second_sync = kasumi::application::execute(
        request(Operation::Sync, environment, "second"));
    ASSERT_TRUE(second_sync.has_value()) << second_sync.error().detail;
    EXPECT_EQ(kasumi::test::read_text(second.local_dir / "file.txt"), "one");

    kasumi::test::write_text(first.local_dir / "file.txt", "two");
    ASSERT_TRUE(kasumi::application::execute(
        request(Operation::Sync, environment, "first")));
    const auto before_preview = kasumi::test::snapshot_tree(remote);
    const auto before_second =
        kasumi::test::read_text(second.local_dir / "file.txt");
    const auto preview = kasumi::application::execute(
        request(Operation::Preview, environment, "second"));
    ASSERT_TRUE(preview.has_value());
    ASSERT_TRUE(std::holds_alternative<PlanReport>(preview->data));
    EXPECT_EQ(kasumi::test::snapshot_tree(remote), before_preview);
    EXPECT_EQ(kasumi::test::read_text(second.local_dir / "file.txt"),
              before_second);
    const auto status = kasumi::application::execute(
        request(Operation::Status, environment, "second"));
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(kasumi::test::snapshot_tree(remote), before_preview);

    ASSERT_TRUE(kasumi::application::execute(
        request(Operation::Sync, environment, "second")));
    EXPECT_EQ(kasumi::test::read_text(second.local_dir / "file.txt"), "two");

    std::filesystem::rename(first.local_dir / "file.txt",
                            first.local_dir / "renamed.txt");
    kasumi::test::write_text(first.local_dir / "added.txt", "added");
    ASSERT_TRUE(kasumi::application::execute(
        request(Operation::Sync, environment, "first")));
    ASSERT_TRUE(kasumi::application::execute(
        request(Operation::Sync, environment, "second")));
    EXPECT_FALSE(std::filesystem::exists(second.local_dir / "file.txt"));
    EXPECT_EQ(kasumi::test::read_text(second.local_dir / "renamed.txt"), "two");
    EXPECT_EQ(kasumi::test::read_text(second.local_dir / "added.txt"), "added");
    ASSERT_TRUE(kasumi::application::execute(
        request(Operation::Sync, environment, "second")));
}

TEST(ApplicationMaintenanceContract,
     NormalSyncTrustsInheritedContentButFsckAndRequiredGetFailClosed) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-fsck-repair");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    const MasterKeyHex key{std::string(64, 'b')};
    ASSERT_TRUE(kasumi::application::create_profile(environment, profile, key));
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "file.txt", "source");
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "remote").string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));

    const auto identifier = content_identifier(storage);
    ASSERT_FALSE(identifier.empty());
    ASSERT_EQ(kasumi::transport::remove(storage, identifier).value(),
              kasumi::transport::Removal::Removed);
    const auto trusted_no_op =
        kasumi::application::execute(request(Operation::Sync, environment));
    ASSERT_TRUE(trusted_no_op.has_value()) << trusted_no_op.error().detail;
    const auto missing =
        kasumi::application::execute(request(Operation::Fsck, environment));
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code,
              kasumi::application::ErrorCode::FsckFailure);
    EXPECT_EQ(kasumi::transport::presence(storage, identifier).value(),
              kasumi::transport::Presence::Absent);

    const Profile receiver{
        "receiver",
        kasumi::test::workspace_path(workspace, "receiver-local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, receiver, key));
    ASSERT_TRUE(std::filesystem::create_directories(receiver.local_dir));
    const auto required = kasumi::application::execute(
        request(Operation::Sync, environment, receiver.name));
    ASSERT_FALSE(required.has_value());
    EXPECT_EQ(required.error().code,
              kasumi::application::ErrorCode::SynchronizationFailure);

    kasumi::test::write_text(kasumi::test::workspace_path(workspace, "remote") /
                                 identifier,
                             "invalid");
    const auto corruption =
        kasumi::application::execute(request(Operation::Fsck, environment));
    ASSERT_FALSE(corruption.has_value());
    EXPECT_EQ(corruption.error().code,
              kasumi::application::ErrorCode::FsckFailure);
    EXPECT_EQ(kasumi::transport::presence(storage, identifier).value(),
              kasumi::transport::Presence::Present);
}

TEST(ApplicationMaintenanceContract,
     FsckWithoutSourceFailsAndPreservesHistory) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-fsck-no-source");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{std::string(64, 'c')}));
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "file.txt", "source");
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "remote").string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));
    const auto identifier = content_identifier(storage);
    ASSERT_FALSE(identifier.empty());
    const auto listing_before = kasumi::transport::list(storage);
    ASSERT_TRUE(listing_before.has_value());
    ASSERT_TRUE(std::filesystem::remove(profile.local_dir / "file.txt"));
    ASSERT_EQ(kasumi::transport::remove(storage, identifier).value(),
              kasumi::transport::Removal::Removed);
    const auto orphan_source =
        kasumi::test::workspace_path(workspace, "orphan.txt");
    kasumi::test::write_text(orphan_source, "orphan");
    ASSERT_TRUE(
        kasumi::transport::put(storage, orphan_source, canonical_orphan()));

    const auto result =
        kasumi::application::execute(request(Operation::Fsck, environment));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, kasumi::application::ErrorCode::FsckFailure);
    const auto listing_after = kasumi::transport::list(storage);
    ASSERT_TRUE(listing_after.has_value());
    for (const auto& object : *listing_before) {
        if (object.starts_with("history/")) {
            EXPECT_NE(std::ranges::find(*listing_after, object),
                      listing_after->end());
        }
    }
    EXPECT_EQ(kasumi::transport::presence(storage, canonical_orphan()).value(),
              kasumi::transport::Presence::Present);
}

TEST(ApplicationMaintenanceContract,
     GarbageCollectQuarantinesOnlyOrphanObjectsAndIsIdempotent) {
    auto workspace = kasumi::test::make_temp_workspace("application-gc");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{std::string(64, 'd')}));
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "file.txt", "source");
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "remote").string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));
    const auto referenced = content_identifier(storage);
    ASSERT_FALSE(referenced.empty());
    const auto orphan = canonical_orphan();
    const auto orphan_source =
        kasumi::test::workspace_path(workspace, "orphan.txt");
    kasumi::test::write_text(orphan_source, "orphan");
    ASSERT_TRUE(kasumi::transport::put(storage, orphan_source, orphan));

    const auto first = kasumi::application::execute(
        request(Operation::GarbageCollect, environment));
    ASSERT_TRUE(first.has_value()) << first.error().detail;
    ASSERT_TRUE(
        std::holds_alternative<kasumi::application::GarbageCollectCompleted>(
            first->data));
    EXPECT_EQ(
        std::get<kasumi::application::GarbageCollectCompleted>(first->data)
            .quarantined_objects,
        1U);
    EXPECT_EQ(kasumi::transport::presence(storage, referenced).value(),
              kasumi::transport::Presence::Present);
    EXPECT_EQ(kasumi::transport::presence(storage, orphan).value(),
              kasumi::transport::Presence::Absent);
    EXPECT_EQ(kasumi::transport::presence(
                  storage, protocol::quarantine_identifier(orphan).value())
                  .value(),
              kasumi::transport::Presence::Present);
    const auto second = kasumi::application::execute(
        request(Operation::GarbageCollect, environment));
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_EQ(
        std::get<kasumi::application::GarbageCollectCompleted>(second->data)
            .quarantined_objects,
        0U);
}

TEST(ApplicationMaintenanceContract, ActiveBarrierBlocksSyncBeforePublication) {
    auto workspace = kasumi::test::make_temp_workspace("application-barrier");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{std::string(64, 'f')}));
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "file.txt", "before");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));

    auto opened = kasumi::transport::open_transport(profile.remote_dir);
    ASSERT_TRUE(opened.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*opened));
    const auto paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, profile.name);
    ASSERT_TRUE(paths.has_value());
    auto barrier = protocol::establish_barrier(*opened, paths->profile_dir);
    ASSERT_TRUE(barrier.has_value()) << barrier.error().detail;

    const auto no_op =
        kasumi::application::execute(request(Operation::Sync, environment));
    ASSERT_TRUE(no_op.has_value()) << no_op.error().detail;

    kasumi::test::write_text(profile.local_dir / "file.txt", "after");
    const auto blocked =
        kasumi::application::execute(request(Operation::Sync, environment));
    ASSERT_FALSE(blocked.has_value());
    EXPECT_EQ(blocked.error().code,
              kasumi::application::ErrorCode::SynchronizationFailure);
    EXPECT_NE(blocked.error().detail.find("GC ativo"), std::string::npos);

    const auto released = protocol::release_registration(*barrier);
    ASSERT_TRUE(released.has_value()) << released.error().detail;
    const auto synchronized =
        kasumi::application::execute(request(Operation::Sync, environment));
    ASSERT_TRUE(synchronized.has_value()) << synchronized.error().detail;
}

TEST(ApplicationMaintenanceContract,
     UnknownStorageIdentifiersAbortMaintenance) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-unknown-identifier");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{std::string(64, 'e')}));
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "file.txt", "source");
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "remote").string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));
    const auto orphan = canonical_orphan();
    const auto orphan_source =
        kasumi::test::workspace_path(workspace, "orphan.txt");
    kasumi::test::write_text(orphan_source, "orphan");
    ASSERT_TRUE(kasumi::transport::put(storage, orphan_source, orphan));
    const auto unknown_source =
        kasumi::test::workspace_path(workspace, "unknown.txt");
    kasumi::test::write_text(unknown_source, "unknown");
    ASSERT_TRUE(kasumi::transport::put(
        storage, unknown_source, "not-a-canonical-hash"));

    const auto gc = kasumi::application::execute(
        request(Operation::GarbageCollect, environment));
    ASSERT_FALSE(gc.has_value());
    EXPECT_EQ(gc.error().code,
              kasumi::application::ErrorCode::GarbageCollectionFailure);
    const auto fsck =
        kasumi::application::execute(request(Operation::Fsck, environment));
    ASSERT_FALSE(fsck.has_value());
    EXPECT_EQ(fsck.error().code, kasumi::application::ErrorCode::FsckFailure);
    EXPECT_EQ(kasumi::transport::presence(storage, orphan).value(),
              kasumi::transport::Presence::Present);
    EXPECT_EQ(
        kasumi::transport::presence(storage, "not-a-canonical-hash").value(),
        kasumi::transport::Presence::Present);
}

} // namespace
