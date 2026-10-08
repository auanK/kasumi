#include "application/execute.hpp"
#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/history.hpp"
#include "application/profile.hpp"
#include "cli/app.hpp"
#include "core/hasher.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/provider_scenarios.hpp"
#include "kasumi/test/scoped_environment.hpp"
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
    const auto key_bytes =
        kasumi::runtime::vault::decode_hex(std::string(64, '6')).value();
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(key_bytes);
    EXPECT_TRUE(std::ranges::any_of(*identifiers, [&](const auto& identifier) {
        return kasumi::application::history_storage::parse_commit_object(
                   layout, identifier)
            .has_value();
    }));
    EXPECT_TRUE(std::ranges::any_of(*identifiers, [&](const auto& identifier) {
        return kasumi::application::history_storage::parse_marker_object(
                   layout, identifier)
            .has_value();
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

    const auto no_op = kasumi::test::scenarios::no_op_sync(environment, "demo");
    ASSERT_TRUE(no_op.has_value()) << no_op.error();
    EXPECT_TRUE(*no_op);
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
    const auto key_bytes =
        kasumi::runtime::vault::decode_hex(std::string(64, '4')).value();
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(key_bytes);
    auto commit = std::ranges::find_if(*listing, [&](const auto& identifier) {
        return kasumi::application::history_storage::parse_commit_object(
                   layout, identifier)
            .has_value();
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
     PreviewAndStatusReportPersistedPendingMaterializations) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-pending-plan");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{std::string(64, '8')}));
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "pending.txt", "payload");
    ASSERT_TRUE(kasumi::application::execute(
        request(Operation::Sync, environment)));

    const auto paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "demo");
    ASSERT_TRUE(paths.has_value());
    auto state = kasumi::state_storage::load_state(paths->database_path);
    ASSERT_TRUE(state.has_value() && *state);
    const auto* row = kasumi::find_row((*state)->tree, "pending.txt");
    ASSERT_NE(row, nullptr);
    (*state)->pending_materializations = {*row};
    ASSERT_TRUE(kasumi::state_storage::save_state(paths->database_path,
                                                  **state));
    ASSERT_TRUE(std::filesystem::remove(profile.local_dir / "pending.txt"));

    for (const auto operation : {Operation::Preview, Operation::Status}) {
        const auto report =
            kasumi::application::execute(request(operation, environment));
        ASSERT_TRUE(report.has_value()) << report.error().detail;
        const auto* plan = std::get_if<PlanReport>(&report->data);
        ASSERT_NE(plan, nullptr);
        ASSERT_EQ(plan->pending_paths.size(), 1U);
        EXPECT_EQ(plan->pending_paths.front(), "pending.txt");
        EXPECT_TRUE(std::ranges::none_of(
            plan->items, [](const kasumi::application::PlanItem& item) {
                return item.action == kasumi::application::PlanAction::
                           DeleteRemote;
            }));
        EXPECT_FALSE(std::filesystem::exists(profile.local_dir / "pending.txt"));
    }
}

TEST(ApplicationMaintenanceContract,
     FsckFailsClosedAndRequiredGetReturnsPartial) {
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
    ASSERT_TRUE(required.has_value()) << required.error().detail;
    const auto* partial = std::get_if<kasumi::application::SyncCompleted>(
        &required->data);
    ASSERT_NE(partial, nullptr);
    EXPECT_TRUE(partial->partial);
    ASSERT_EQ(partial->pending_paths.size(), 1U);
    EXPECT_EQ(partial->pending_paths.front(), "file.txt");
    EXPECT_FALSE(std::filesystem::exists(receiver.local_dir / "file.txt"));

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

    const Profile corrupt_receiver{
        "corrupt_receiver",
        kasumi::test::workspace_path(workspace, "corrupt-receiver"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, corrupt_receiver, key));
    ASSERT_TRUE(std::filesystem::create_directories(
        corrupt_receiver.local_dir));
    const auto corrupt_download = kasumi::application::execute(
        request(Operation::Sync, environment, corrupt_receiver.name));
    ASSERT_FALSE(corrupt_download.has_value());
    EXPECT_EQ(corrupt_download.error().code,
              kasumi::application::ErrorCode::SynchronizationFailure);
    EXPECT_FALSE(std::filesystem::exists(corrupt_receiver.local_dir / "file.txt"));
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
    const auto key_bytes = *kasumi::hash_from_hex(std::string(64, 'd'));
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key_arr{};
    for (std::size_t i = 0; i < key_arr.size(); ++i) {
        key_arr[i] = static_cast<std::uint8_t>(key_bytes[i]);
    }
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(key_arr);
    EXPECT_EQ(
        kasumi::transport::presence(
            storage, protocol::quarantine_identifier(layout, orphan).value())
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
    const auto key_bytes = *kasumi::hash_from_hex(std::string(64, 'f'));
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key_arr{};
    for (std::size_t i = 0; i < key_arr.size(); ++i) {
        key_arr[i] = static_cast<std::uint8_t>(key_bytes[i]);
    }
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(key_arr);
    auto barrier =
        protocol::establish_barrier(*opened, layout, paths->profile_dir);
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
    EXPECT_NE(blocked.error().detail.find("GC active"), std::string::npos);

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

TEST(SyncMaintenanceTest, EmitsGarbageCollectProgressStagesInDeterministicOrder) {
    auto workspace = kasumi::test::make_temp_workspace("gc-progress-order");
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

    const auto orphan = canonical_orphan();
    const auto orphan_source =
        kasumi::test::workspace_path(workspace, "orphan.txt");
    kasumi::test::write_text(orphan_source, "orphan");
    ASSERT_TRUE(kasumi::transport::put(storage, orphan_source, orphan));

    std::vector<kasumi::application::GarbageCollectProgress> progress_events;
    auto req = request(Operation::GarbageCollect, environment);
    req.on_progress = [&](const kasumi::application::ExecutionProgress& p) {
        if (const auto* gc = std::get_if<kasumi::application::GarbageCollectProgress>(&p)) {
            progress_events.push_back(*gc);
        }
    };
    const auto gc = kasumi::application::execute(req);
    ASSERT_TRUE(gc.has_value()) << gc.error().detail;

    ASSERT_GE(progress_events.size(), 5U);
    EXPECT_EQ(progress_events[0].stage, kasumi::application::GarbageCollectStage::Preparing);
    EXPECT_EQ(progress_events[1].stage, kasumi::application::GarbageCollectStage::CheckingQuarantine);
    EXPECT_EQ(progress_events[2].stage, kasumi::application::GarbageCollectStage::Analyzing);
    EXPECT_FALSE(progress_events[2].candidate_count.has_value());
    EXPECT_EQ(progress_events[3].stage, kasumi::application::GarbageCollectStage::Analyzing);
    ASSERT_TRUE(progress_events[3].candidate_count.has_value());
    EXPECT_EQ(*progress_events[3].candidate_count, 1U);
    EXPECT_EQ(progress_events[4].stage, kasumi::application::GarbageCollectStage::Applying);
    EXPECT_EQ(progress_events.back().stage, kasumi::application::GarbageCollectStage::Finalizing);
}

TEST(SyncMaintenanceTest, EmitsGarbageCollectProgressOmittingApplyingWhenNoCandidates) {
    auto workspace = kasumi::test::make_temp_workspace("gc-progress-no-cand");
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

    std::vector<kasumi::application::GarbageCollectProgress> progress_events;
    auto req = request(Operation::GarbageCollect, environment);
    req.on_progress = [&](const kasumi::application::ExecutionProgress& p) {
        if (const auto* gc = std::get_if<kasumi::application::GarbageCollectProgress>(&p)) {
            progress_events.push_back(*gc);
        }
    };
    const auto gc = kasumi::application::execute(req);
    ASSERT_TRUE(gc.has_value()) << gc.error().detail;

    ASSERT_GE(progress_events.size(), 4U);
    EXPECT_EQ(progress_events[0].stage, kasumi::application::GarbageCollectStage::Preparing);
    EXPECT_EQ(progress_events[1].stage, kasumi::application::GarbageCollectStage::CheckingQuarantine);
    EXPECT_EQ(progress_events[2].stage, kasumi::application::GarbageCollectStage::Analyzing);
    EXPECT_EQ(progress_events[3].stage, kasumi::application::GarbageCollectStage::Analyzing);
    ASSERT_TRUE(progress_events[3].candidate_count.has_value());
    EXPECT_EQ(*progress_events[3].candidate_count, 0U);
    EXPECT_EQ(progress_events.back().stage, kasumi::application::GarbageCollectStage::Finalizing);

    for (const auto& event : progress_events) {
        EXPECT_NE(event.stage, kasumi::application::GarbageCollectStage::Applying);
    }
}

TEST(SyncMaintenanceTest, GarbageCollectProgressDoesNotAlterResultOrState) {
    auto workspace = kasumi::test::make_temp_workspace("gc-progress-invariance");
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

    const auto orphan = canonical_orphan();
    const auto orphan_source =
        kasumi::test::workspace_path(workspace, "orphan.txt");
    kasumi::test::write_text(orphan_source, "orphan");
    ASSERT_TRUE(kasumi::transport::put(storage, orphan_source, orphan));

    // Run without progress callback
    auto req_plain = request(Operation::GarbageCollect, environment);
    const auto gc_plain = kasumi::application::execute(req_plain);
    ASSERT_TRUE(gc_plain.has_value());
    const auto data_plain = std::get<kasumi::application::GarbageCollectCompleted>(gc_plain->data);

    // Verify 1 quarantined
    EXPECT_EQ(data_plain.candidate_objects, 1U);
    EXPECT_EQ(data_plain.quarantined_objects, 1U);
}

TEST(SyncMaintenanceTest, FsckPublishesOrderedStagesAndAuthenticatedTotals) {
    auto workspace = kasumi::test::make_temp_workspace("fsck-progress-stages");
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
    ASSERT_TRUE(kasumi::transport::initialize(*opened));
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, environment)));

    std::vector<kasumi::application::FsckProgress> events;
    auto req = request(Operation::Fsck, environment);
    req.on_progress = [&](const kasumi::application::ExecutionProgress& progress) {
        if (const auto* fsck = std::get_if<kasumi::application::FsckProgress>(&progress)) {
            events.push_back(*fsck);
        }
    };
    const auto result = kasumi::application::execute(std::move(req));
    ASSERT_TRUE(result.has_value()) << (result ? "" : result.error().detail);

    ASSERT_EQ(events.size(), 6U);
    EXPECT_EQ(events[0].stage, kasumi::application::FsckStage::Preparing);
    EXPECT_FALSE(events[0].total_objects.has_value());
    EXPECT_EQ(events[1].stage, kasumi::application::FsckStage::Observing);
    EXPECT_FALSE(events[1].total_objects.has_value());
    EXPECT_EQ(events[2].stage, kasumi::application::FsckStage::Analyzing);
    EXPECT_FALSE(events[2].total_objects.has_value());
    EXPECT_EQ(events[3].stage, kasumi::application::FsckStage::AuditingContent);
    EXPECT_EQ(events[3].completed_objects, 0U);
    EXPECT_EQ(events[3].total_objects, 1U);
    EXPECT_EQ(events[3].completed_plaintext_bytes, 0U);
    EXPECT_EQ(events[3].total_plaintext_bytes, 6U);
    EXPECT_EQ(events[4].completed_objects, 1U);
    EXPECT_EQ(events[4].completed_plaintext_bytes, 6U);
    EXPECT_EQ(events[5].stage, kasumi::application::FsckStage::Finalizing);
    EXPECT_EQ(events[5].completed_objects, 1U);
    EXPECT_EQ(events[5].completed_plaintext_bytes, 6U);
}

std::string content_id_for(const std::string& master_hex,
                           std::string_view plaintext) {
    const auto key = kasumi::runtime::vault::decode_hex(master_hex);
    if (!key) {
        return {};
    }
    return kasumi::crypto::content_identifier(
        *key, kasumi::hasher::hash_string(plaintext));
}

int run_resolve_missing_cli(std::string profile = "demo") {
    char arg0[] = "kasumi";
    char arg1[] = "resolve-missing";
    std::vector<char> profile_arg(profile.begin(), profile.end());
    profile_arg.push_back('\0');
    char* argv[] = {arg0, arg1, profile_arg.data()};
    testing::internal::CaptureStdout();
    const auto exit_code = kasumi::cli::run(3, argv);
    const auto output = testing::internal::GetCapturedStdout();
    if (exit_code != 0) {
        std::cerr << "CLI output (code " << exit_code << "): " << output << "\n";
    }
    return exit_code;
}

struct RecoveryFixture {
    kasumi::test::TempWorkspace workspace;
    std::filesystem::path remote_dir;
    std::string master_hex;
    ExecutionEnvironment env_a;
    std::filesystem::path local_a;
    Profile profile_a;

#if defined(_WIN32)
    kasumi::test::ScopedWindowsEnvironmentVariable win_app_root;
#endif
    kasumi::test::ScopedEnvironmentVariable app_root;
    kasumi::test::ScopedEnvironmentVariable master_key_env;
    ExecutionEnvironment env_b;
    std::filesystem::path local_b;
    Profile profile_b;
};

RecoveryFixture make_recovery_fixture(const std::string& test_name) {
    auto ws = kasumi::test::make_temp_workspace(test_name);
    const auto remote = kasumi::test::workspace_path(ws, "remote");
    const std::string hex_key(64, '9');
    const ExecutionEnvironment a_env{
        kasumi::test::workspace_path(ws, "a_app")};
    const auto a_local = kasumi::test::workspace_path(ws, "a_local");
    const Profile a_prof{"demo", a_local, remote.string()};

#if defined(_WIN32)
    auto win_root = kasumi::test::scoped_windows_environment_variable(
        L"APPDATA", kasumi::test::workspace_path(ws, "b_appdata").wstring());
    auto root = kasumi::test::scoped_environment_variable(
        "APPDATA", kasumi::test::workspace_path(ws, "b_appdata").string());
#else
    auto root = kasumi::test::scoped_environment_variable(
        "XDG_CONFIG_HOME",
        kasumi::test::workspace_path(ws, "b_config").string());
#endif
    auto mkey = kasumi::test::scoped_environment_variable("KASUMI_MASTER_KEY",
                                                          hex_key);
    const auto b_env = kasumi::application::default_execution_environment();
    const auto b_local = kasumi::test::workspace_path(ws, "b_local");
    const Profile b_prof{"demo", b_local, remote.string()};
    std::filesystem::create_directories(a_env.app_data_dir);
    std::filesystem::create_directories(b_env.app_data_dir);

    return RecoveryFixture{
        .workspace = std::move(ws),
        .remote_dir = remote,
        .master_hex = hex_key,
        .env_a = a_env,
        .local_a = a_local,
        .profile_a = a_prof,
#if defined(_WIN32)
        .win_app_root = std::move(win_root),
#endif
        .app_root = std::move(root),
        .master_key_env = std::move(mkey),
        .env_b = b_env,
        .local_b = b_local,
        .profile_b = b_prof,
    };
}

TEST(ApplicationRecoveryContract,
     ResolveMissingPublishesLogicalDeletionForUnrecoverablePendingContent) {
    auto f = make_recovery_fixture("recovery-resolve-unrecoverable");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "lost.txt", "lost-payload");
    kasumi::test::write_text(f.local_a / "retained.txt", "retained-payload");
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto lost_cid = content_id_for(f.master_hex, "lost-payload");
    const auto retained_cid = content_id_for(f.master_hex, "retained-payload");
    ASSERT_FALSE(lost_cid.empty());
    ASSERT_FALSE(retained_cid.empty());
    ASSERT_EQ(kasumi::transport::presence(storage, lost_cid).value(),
              kasumi::transport::Presence::Present);
    ASSERT_TRUE(kasumi::transport::remove(storage, lost_cid));
    ASSERT_EQ(kasumi::transport::presence(storage, lost_cid).value(),
              kasumi::transport::Presence::Absent);

    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value());
    const auto* b_summary =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(b_summary, nullptr);
    EXPECT_TRUE(b_summary->partial);
    ASSERT_EQ(b_summary->pending_paths.size(), 1U);
    EXPECT_EQ(b_summary->pending_paths.front(), "lost.txt");

    EXPECT_FALSE(std::filesystem::exists(f.local_b / "lost.txt"));
    EXPECT_TRUE(std::filesystem::exists(f.local_b / "retained.txt"));
    EXPECT_EQ(kasumi::transport::presence(storage, lost_cid).value(),
              kasumi::transport::Presence::Absent);
    EXPECT_EQ(kasumi::transport::presence(storage, retained_cid).value(),
              kasumi::transport::Presence::Present);

    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    auto state_b = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(state_b.has_value() && *state_b);
    EXPECT_NE(kasumi::find_row((*state_b)->tree, "lost.txt"), nullptr);
    EXPECT_NE(kasumi::find_row((*state_b)->tree, "retained.txt"), nullptr);
    ASSERT_EQ((*state_b)->pending_materializations.size(), 1U);
    EXPECT_EQ((*state_b)->pending_materializations.front().path, "lost.txt");

    const auto status =
        kasumi::application::execute(request(Operation::Status, f.env_b));
    ASSERT_TRUE(status.has_value());
    const auto* plan = std::get_if<PlanReport>(&status->data);
    ASSERT_NE(plan, nullptr);
    ASSERT_EQ(plan->pending_paths.size(), 1U);
    EXPECT_EQ(plan->pending_paths.front(), "lost.txt");
    EXPECT_TRUE(std::ranges::none_of(plan->items, [](const auto& it) {
        return it.action == kasumi::application::PlanAction::DeleteRemote;
    }));

    const auto normal_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(normal_sync.has_value());
    const auto* normal_comp =
        std::get_if<kasumi::application::SyncCompleted>(&normal_sync->data);
    ASSERT_NE(normal_comp, nullptr);
    EXPECT_TRUE(normal_comp->partial);

    const auto exit_code = run_resolve_missing_cli("demo");
    ASSERT_EQ(exit_code, 0);

    auto post_state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(post_state.has_value() && *post_state);
    EXPECT_EQ(kasumi::find_row((*post_state)->tree, "lost.txt"), nullptr);
    EXPECT_NE(kasumi::find_row((*post_state)->tree, "retained.txt"), nullptr);
    EXPECT_TRUE((*post_state)->pending_materializations.empty());
    EXPECT_FALSE(std::filesystem::exists(f.local_b / "lost.txt"));
    EXPECT_TRUE(std::filesystem::exists(f.local_b / "retained.txt"));

    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));
    EXPECT_FALSE(std::filesystem::exists(f.local_a / "lost.txt"));
    EXPECT_TRUE(std::filesystem::exists(f.local_a / "retained.txt"));
}

TEST(ApplicationRecoveryContract,
     NormalSyncPreservesPendingMaterializationWithoutDeleteRemote) {
    auto f = make_recovery_fixture("recovery-normal-sync-preserves");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "lost.txt", "lost-payload");
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto lost_cid = content_id_for(f.master_hex, "lost-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, lost_cid));

    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value());
    const auto* b_summary =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(b_summary, nullptr);
    EXPECT_TRUE(b_summary->partial);
    ASSERT_EQ(b_summary->pending_paths.size(), 1U);

    EXPECT_FALSE(std::filesystem::exists(f.local_b / "lost.txt"));
    EXPECT_EQ(kasumi::transport::presence(storage, lost_cid).value(),
              kasumi::transport::Presence::Absent);

    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());

    const auto normal_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(normal_sync.has_value());
    const auto* comp =
        std::get_if<kasumi::application::SyncCompleted>(&normal_sync->data);
    ASSERT_NE(comp, nullptr);
    EXPECT_TRUE(comp->partial);
    ASSERT_EQ(comp->pending_paths.size(), 1U);
    EXPECT_EQ(comp->pending_paths.front(), "lost.txt");

    auto state_b = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(state_b.has_value() && *state_b);
    EXPECT_NE(kasumi::find_row((*state_b)->tree, "lost.txt"), nullptr);
    ASSERT_EQ((*state_b)->pending_materializations.size(), 1U);
    EXPECT_EQ((*state_b)->pending_materializations.front().path, "lost.txt");

    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));
    EXPECT_TRUE(std::filesystem::exists(f.local_a / "lost.txt"));
}

TEST(ApplicationRecoveryContract,
     ResolveMissingRefusesLogicalDeletionWhenRemotePayloadReappears) {
    auto f = make_recovery_fixture("recovery-remote-payload-reappears");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "lost.txt", "lost-payload");
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto lost_cid = content_id_for(f.master_hex, "lost-payload");
    const auto saved_ciphertext =
        kasumi::test::workspace_path(f.workspace, "saved_lost.ciphertext");
    ASSERT_TRUE(kasumi::transport::get(storage, lost_cid, saved_ciphertext));
    ASSERT_TRUE(kasumi::transport::remove(storage, lost_cid));

    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value());
    const auto* b_summary =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(b_summary, nullptr);
    EXPECT_TRUE(b_summary->partial);
    ASSERT_EQ(b_summary->pending_paths.size(), 1U);

    EXPECT_FALSE(std::filesystem::exists(f.local_b / "lost.txt"));
    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    auto state_b = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(state_b.has_value() && *state_b);
    EXPECT_NE(kasumi::find_row((*state_b)->tree, "lost.txt"), nullptr);
    ASSERT_EQ((*state_b)->pending_materializations.size(), 1U);

    ASSERT_TRUE(kasumi::transport::put(storage, saved_ciphertext, lost_cid));
    ASSERT_EQ(kasumi::transport::presence(storage, lost_cid).value(),
              kasumi::transport::Presence::Present);

    const auto exit_code = run_resolve_missing_cli("demo");
    ASSERT_EQ(exit_code, 0);

    auto post_state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(post_state.has_value() && *post_state);
    EXPECT_NE(kasumi::find_row((*post_state)->tree, "lost.txt"), nullptr);

    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_b)));
    EXPECT_TRUE(std::filesystem::exists(f.local_b / "lost.txt"));
}

TEST(ApplicationRecoveryContract,
     ResolveMissingPreservesPathWhenLocalCompatibleSourceReappears) {
    auto f = make_recovery_fixture("recovery-local-source-reappears");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "lost.txt", "lost-payload");
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto lost_cid = content_id_for(f.master_hex, "lost-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, lost_cid));

    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value());
    const auto* b_summary =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(b_summary, nullptr);
    EXPECT_TRUE(b_summary->partial);

    EXPECT_FALSE(std::filesystem::exists(f.local_b / "lost.txt"));
    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());

    kasumi::test::write_text(f.local_b / "lost.txt", "lost-payload");

    const auto exit_code = run_resolve_missing_cli("demo");
    ASSERT_EQ(exit_code, 0);

    auto post_state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(post_state.has_value() && *post_state);
    EXPECT_NE(kasumi::find_row((*post_state)->tree, "lost.txt"), nullptr);

    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_b)));
    EXPECT_EQ(kasumi::transport::presence(storage, lost_cid).value(),
              kasumi::transport::Presence::Present);
}

TEST(ApplicationRecoveryContract,
     ResolveMissingOperatesAtomicallyOnMultiplePendingPaths) {
    auto f = make_recovery_fixture("recovery-atomic-multiple-paths");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "lost1.txt", "payload-1");
    kasumi::test::write_text(f.local_a / "lost2.txt", "payload-2");
    kasumi::test::write_text(f.local_a / "retained.txt", "payload-retained");
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto cid1 = content_id_for(f.master_hex, "payload-1");
    const auto cid2 = content_id_for(f.master_hex, "payload-2");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid1));
    ASSERT_TRUE(kasumi::transport::remove(storage, cid2));

    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value());
    const auto* b_summary =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(b_summary, nullptr);
    EXPECT_TRUE(b_summary->partial);
    ASSERT_EQ(b_summary->pending_paths.size(), 2U);

    EXPECT_FALSE(std::filesystem::exists(f.local_b / "lost1.txt"));
    EXPECT_FALSE(std::filesystem::exists(f.local_b / "lost2.txt"));
    EXPECT_TRUE(std::filesystem::exists(f.local_b / "retained.txt"));
    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    auto state_b = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(state_b.has_value() && *state_b);
    EXPECT_NE(kasumi::find_row((*state_b)->tree, "lost1.txt"), nullptr);
    EXPECT_NE(kasumi::find_row((*state_b)->tree, "lost2.txt"), nullptr);
    ASSERT_EQ((*state_b)->pending_materializations.size(), 2U);

    const auto exit_code = run_resolve_missing_cli("demo");
    ASSERT_EQ(exit_code, 0);

    auto post_state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(post_state.has_value() && *post_state);
    EXPECT_EQ(kasumi::find_row((*post_state)->tree, "lost1.txt"), nullptr);
    EXPECT_EQ(kasumi::find_row((*post_state)->tree, "lost2.txt"), nullptr);
    EXPECT_NE(kasumi::find_row((*post_state)->tree, "retained.txt"), nullptr);
    EXPECT_TRUE((*post_state)->pending_materializations.empty());
}

TEST(ApplicationRecoveryContract,
     ResolveMissingPreservesRecoverablePendingPathWhileResolvingUnrecoverable) {
    auto f = make_recovery_fixture("recovery-selective-unrecoverable");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "lost_unrecov.txt", "unrecov-payload");
    kasumi::test::write_text(f.local_a / "lost_recov.txt", "recov-payload");
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto cid_unrecov = content_id_for(f.master_hex, "unrecov-payload");
    const auto cid_recov = content_id_for(f.master_hex, "recov-payload");
    const auto saved_recov =
        kasumi::test::workspace_path(f.workspace, "saved_recov.ciphertext");
    ASSERT_TRUE(kasumi::transport::get(storage, cid_recov, saved_recov));
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_unrecov));
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_recov));

    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value());
    const auto* b_summary =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(b_summary, nullptr);
    EXPECT_TRUE(b_summary->partial);
    ASSERT_EQ(b_summary->pending_paths.size(), 2U);

    EXPECT_FALSE(std::filesystem::exists(f.local_b / "lost_unrecov.txt"));
    EXPECT_FALSE(std::filesystem::exists(f.local_b / "lost_recov.txt"));

    ASSERT_TRUE(kasumi::transport::put(storage, saved_recov, cid_recov));

    const auto exit_code = run_resolve_missing_cli("demo");
    ASSERT_EQ(exit_code, 0);

    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    auto post_state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(post_state.has_value() && *post_state);
    EXPECT_EQ(kasumi::find_row((*post_state)->tree, "lost_unrecov.txt"), nullptr);
    EXPECT_NE(kasumi::find_row((*post_state)->tree, "lost_recov.txt"), nullptr);
    EXPECT_TRUE(std::ranges::none_of(
        (*post_state)->pending_materializations,
        [](const auto& r) { return r.path == "lost_unrecov.txt"; }));
}

TEST(ApplicationRecoveryContract,
     ResolveMissingLeavesReappearedPendingContentForNormalSync) {
    auto f = make_recovery_fixture("recovery-mixed-pending-content");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "a.txt", "unrecoverable-payload");
    kasumi::test::write_text(f.local_a / "b.txt", "recoverable-payload");
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto cid_a = content_id_for(f.master_hex, "unrecoverable-payload");
    const auto cid_b = content_id_for(f.master_hex, "recoverable-payload");
    const auto saved_b =
        kasumi::test::workspace_path(f.workspace, "saved_b.ciphertext");
    ASSERT_TRUE(kasumi::transport::get(storage, cid_b, saved_b));
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_a));
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_b));

    const auto initial_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(initial_sync.has_value());
    const auto* initial =
        std::get_if<kasumi::application::SyncCompleted>(&initial_sync->data);
    ASSERT_NE(initial, nullptr);
    ASSERT_EQ(initial->pending_paths.size(), 2U);
    EXPECT_FALSE(std::filesystem::exists(f.local_b / "a.txt"));
    EXPECT_FALSE(std::filesystem::exists(f.local_b / "b.txt"));

    ASSERT_TRUE(kasumi::transport::put(storage, saved_b, cid_b));
    ASSERT_EQ(kasumi::transport::presence(storage, cid_a).value(),
              kasumi::transport::Presence::Absent);

    ASSERT_EQ(run_resolve_missing_cli(), 0);

    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    const auto state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ(kasumi::find_row((*state)->tree, "a.txt"), nullptr);
    EXPECT_NE(kasumi::find_row((*state)->tree, "b.txt"), nullptr);
    ASSERT_EQ((*state)->pending_materializations.size(), 1U);
    EXPECT_EQ((*state)->pending_materializations.front().path, "b.txt");
    EXPECT_FALSE(std::filesystem::exists(f.local_b / "a.txt"));
    EXPECT_FALSE(std::filesystem::exists(f.local_b / "b.txt"));

    const auto later_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(later_sync.has_value());
    const auto* completed =
        std::get_if<kasumi::application::SyncCompleted>(&later_sync->data);
    ASSERT_NE(completed, nullptr);
    EXPECT_TRUE(completed->pending_paths.empty());
    EXPECT_TRUE(std::filesystem::exists(f.local_b / "b.txt"));
    EXPECT_EQ(kasumi::test::read_text(f.local_b / "b.txt"),
              "recoverable-payload");
    EXPECT_FALSE(std::filesystem::exists(f.local_b / "a.txt"));

    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));
    EXPECT_FALSE(std::filesystem::exists(f.local_a / "a.txt"));
}

TEST(ApplicationRecoveryContract,
     ResolveMissingPreservesExistingContentObjects) {
    auto f = make_recovery_fixture("recovery-preserves-existing-content");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "lost.txt", "lost-payload");
    kasumi::test::write_text(f.local_a / "retained.txt", "retained-payload");
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto lost_cid = content_id_for(f.master_hex, "lost-payload");
    const auto retained_cid = content_id_for(f.master_hex, "retained-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, lost_cid));

    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value());
    const auto* b_summary =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(b_summary, nullptr);
    EXPECT_TRUE(b_summary->partial);

    ASSERT_EQ(kasumi::transport::presence(storage, retained_cid).value(),
              kasumi::transport::Presence::Present);

    const auto exit_code = run_resolve_missing_cli("demo");
    ASSERT_EQ(exit_code, 0);

    EXPECT_EQ(kasumi::transport::presence(storage, retained_cid).value(),
              kasumi::transport::Presence::Present);
}

TEST(ApplicationRecoveryContract,
     ResolveMissingFailsClosedWhenUnrelatedLocalDeletionExists) {
    auto f = make_recovery_fixture("recovery-unrelated-local-deletion");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "lost.txt", "lost-payload");
    kasumi::test::write_text(f.local_a / "unrelated.txt", "unrelated-payload");
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto lost_cid = content_id_for(f.master_hex, "lost-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, lost_cid));

    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value());
    const auto* b_summary =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(b_summary, nullptr);
    EXPECT_TRUE(b_summary->partial);
    ASSERT_EQ(b_summary->pending_paths.size(), 1U);
    EXPECT_EQ(b_summary->pending_paths.front(), "lost.txt");

    // Client B locally deletes unrelated.txt
    ASSERT_TRUE(std::filesystem::remove(f.local_b / "unrelated.txt"));

    // Running resolve-missing must fail closed: no unrelated deletions allowed!
    const auto exit_code = run_resolve_missing_cli("demo");
    EXPECT_NE(exit_code, 0);

    // Verify unrelated.txt was NOT deleted remotely in storage
    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    auto post_state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(post_state.has_value() && *post_state);
    EXPECT_NE(kasumi::find_row((*post_state)->tree, "unrelated.txt"), nullptr);
    EXPECT_NE(kasumi::find_row((*post_state)->tree, "lost.txt"), nullptr);
}

TEST(ApplicationRecoveryContract,
     ResolveMissingFailsClosedWhenUnrelatedLocalModificationsExist) {
    auto f = make_recovery_fixture("recovery-unrelated-local-modification");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "lost.txt", "lost-payload");
    kasumi::test::write_text(f.local_a / "edited.txt", "original-content");
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto lost_cid = content_id_for(f.master_hex, "lost-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, lost_cid));

    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value());
    const auto* b_summary =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(b_summary, nullptr);
    EXPECT_TRUE(b_summary->partial);

    // Client B modifies edited.txt locally
    kasumi::test::write_text(f.local_b / "edited.txt", "modified-content");

    // Running resolve-missing must fail closed: no uploads or unrelated operations!
    const auto exit_code = run_resolve_missing_cli("demo");
    EXPECT_NE(exit_code, 0);

    // Verify state was not modified / new commit with modified content was not published
    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    auto post_state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(post_state.has_value() && *post_state);
    const auto* edited_row = kasumi::find_row((*post_state)->tree, "edited.txt");
    ASSERT_NE(edited_row, nullptr);
    EXPECT_EQ(edited_row->hash, kasumi::hasher::hash_string("original-content"));
}

TEST(ApplicationRecoveryContract,
     ResolveMissingFailsClosedWhenPendingPathReplacedLocallyByDirectory) {
    auto f = make_recovery_fixture("recovery-pending-replaced-by-directory");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "lost.txt", "lost-payload");
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto lost_cid = content_id_for(f.master_hex, "lost-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, lost_cid));

    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value());
    const auto* b_summary =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(b_summary, nullptr);
    EXPECT_TRUE(b_summary->partial);

    // Client B creates a directory at lost.txt locally, making it ineligible!
    ASSERT_TRUE(std::filesystem::create_directories(f.local_b / "lost.txt"));

    // Running resolve-missing must fail closed: cannot resolve ineligible path!
    const auto exit_code = run_resolve_missing_cli("demo");
    EXPECT_NE(exit_code, 0);

    // Verify remote tree still has lost.txt as file, not converted to directory or deleted
    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    auto post_state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(post_state.has_value() && *post_state);
    const auto* lost_row = kasumi::find_row((*post_state)->tree, "lost.txt");
    ASSERT_NE(lost_row, nullptr);
    EXPECT_FALSE(lost_row->is_directory);
}

} // namespace
