#include "application/execute.hpp"
#include "application/history_storage/activity.hpp"
#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/inspection/inspect.hpp"
#include "application/observation/history.hpp"
#include "application/profile.hpp"
#include "application/sync/publication.hpp"
#include "cli/app.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "kasumi/test/capture.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/provider_scenarios.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "runtime/machine.hpp"
#include "runtime/paths.hpp"
#include "runtime/vault.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <iostream>
#include <sstream>
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

struct MaintenanceEnv {
    kasumi::test::TempWorkspace workspace;
    ExecutionEnvironment environment;
    Profile profile;
    std::filesystem::path remote;
    Credentials credentials{NoCredentials{}};
};

MaintenanceEnv make_maintenance_env(std::string_view label,
                                    char key_hex_char,
                                    std::string_view profile_name = "demo") {
    auto workspace = kasumi::test::make_temp_workspace(label);
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const Profile profile{std::string(profile_name),
                          kasumi::test::workspace_path(workspace, "local"),
                          remote.string()};
    EXPECT_TRUE(
        kasumi::application::create_profile(
            environment, profile, MasterKeyHex{std::string(64, key_hex_char)})
            .has_value());
    return {.workspace = std::move(workspace),
            .environment = environment,
            .profile = profile,
            .remote = remote};
}

std::optional<kasumi::transport::Transport>
open_initialized_storage(const std::string& location) {
    auto opened = kasumi::transport::open_transport(location);
    if (!opened || !kasumi::transport::initialize(*opened)) {
        return std::nullopt;
    }
    return std::move(*opened);
}

TEST(ApplicationMaintenanceContract,
     PublicSyncPreviewStatusAndFsckRemainAvailable) {
    auto [workspace, environment, profile, remote, credentials] =
        make_maintenance_env("application-sync-maintenance", '7');
    kasumi::test::write_text(profile.local_dir / "file.txt", "one");

    auto opened = open_initialized_storage(profile.remote_dir);
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
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
    auto [workspace, environment, profile, remote, credentials] =
        make_maintenance_env("application-unknown-objects", '6');
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    auto opened = open_initialized_storage(profile.remote_dir);
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
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
    ASSERT_TRUE(kasumi::state_storage::initialize(paths->database_path));

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
    auto [workspace, environment, profile, remote, credentials] =
        make_maintenance_env("application-read-only-absent-remote", '2');
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
    auto [workspace, environment, profile, remote, credentials] =
        make_maintenance_env("application-sync-no-op", '3');
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "file.txt", "same");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));

    const auto paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "demo");
    ASSERT_TRUE(paths.has_value());
    const auto state_before =
        kasumi::state_storage::load_state(paths->database_path);
    ASSERT_TRUE(state_before.has_value() && *state_before);
    const auto remote_before = kasumi::test::snapshot_tree(profile.remote_dir);
    auto opened = open_initialized_storage(profile.remote_dir);
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    const auto listing_before = kasumi::transport::list(storage);
    ASSERT_TRUE(listing_before.has_value());

    const auto no_op = kasumi::test::scenarios::no_op_sync(environment, "demo");
    ASSERT_TRUE(no_op.has_value()) << no_op.error();
    EXPECT_TRUE(*no_op);
    const auto state_after =
        kasumi::state_storage::load_state(paths->database_path);
    ASSERT_TRUE(state_after.has_value() && *state_after);
    EXPECT_EQ((*state_after)->tree, (*state_before)->tree);
    EXPECT_EQ((*state_after)->height, (*state_before)->height);
    EXPECT_EQ((*state_after)->commit_id, (*state_before)->commit_id);
    EXPECT_EQ((*state_after)->ciphertext_id, (*state_before)->ciphertext_id);
    EXPECT_EQ((*state_after)->epoch_id, (*state_before)->epoch_id);
    EXPECT_EQ((*state_after)->epoch_sequence, (*state_before)->epoch_sequence);
    EXPECT_EQ((*state_after)->pending_materializations,
              (*state_before)->pending_materializations);
    EXPECT_EQ((*state_after)->storage_manifest,
              (*state_before)->storage_manifest);
    EXPECT_EQ(kasumi::test::snapshot_tree(profile.remote_dir), remote_before);
    const auto listing_after = kasumi::transport::list(storage);
    ASSERT_TRUE(listing_after.has_value());
    EXPECT_EQ(*listing_after, *listing_before);
    EXPECT_FALSE(
        std::filesystem::exists(paths->profile_dir / "transaction.bin.enc"));
    const auto activity =
        kasumi::application::inspect_profile_activity(environment, "demo");
    ASSERT_TRUE(activity.last_attempt.has_value());
    EXPECT_EQ(activity.last_attempt->status,
              kasumi::application::ProfileExecutionStatus::SucceededNoChanges);
    ASSERT_TRUE(activity.last_complete_sync.has_value());
    EXPECT_EQ(activity.last_complete_sync->status,
              kasumi::application::ProfileExecutionStatus::SucceededNoChanges);
}

TEST(ApplicationMaintenanceContract,
     StateOnlyRejectsAnUnreachableLogicalHeadWithoutCreatingState) {
    auto [workspace, environment, profile, remote, credentials] =
        make_maintenance_env("application-state-only-unreachable", '4');
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "file.txt", "same");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));

    const auto paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "demo");
    ASSERT_TRUE(paths.has_value());
    ASSERT_TRUE(std::filesystem::remove(paths->database_path));
    ASSERT_TRUE(kasumi::state_storage::initialize(paths->database_path));
    auto opened = open_initialized_storage(profile.remote_dir);
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
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
    ASSERT_TRUE(kasumi::state_storage::validate(paths->database_path));
    const auto state = kasumi::state_storage::load_state(paths->database_path);
    ASSERT_TRUE(state.has_value());
    EXPECT_FALSE(state->has_value());
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
    auto [workspace, environment, profile, remote, credentials] =
        make_maintenance_env("application-pending-plan", '8');
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "pending.txt", "payload");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));

    const auto paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "demo");
    ASSERT_TRUE(paths.has_value());
    auto state = kasumi::state_storage::load_state(paths->database_path);
    ASSERT_TRUE(state.has_value() && *state);
    const auto* row = kasumi::find_row((*state)->tree, "pending.txt");
    ASSERT_NE(row, nullptr);
    (*state)->pending_materializations = {*row};
    ASSERT_TRUE(
        kasumi::state_storage::save_state(paths->database_path, **state));
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
                return item.action ==
                       kasumi::application::PlanAction::DeleteRemote;
            }));
        EXPECT_FALSE(
            std::filesystem::exists(profile.local_dir / "pending.txt"));
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
    const auto no_op =
        kasumi::application::execute(request(Operation::Sync, environment));
    ASSERT_TRUE(no_op.has_value()) << no_op.error().detail;
    EXPECT_EQ(kasumi::transport::presence(storage, identifier).value(),
              kasumi::transport::Presence::Absent);
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
    const auto* partial =
        std::get_if<kasumi::application::SyncCompleted>(&required->data);
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
    ASSERT_TRUE(
        std::filesystem::create_directories(corrupt_receiver.local_dir));
    const auto corrupt_download = kasumi::application::execute(
        request(Operation::Sync, environment, corrupt_receiver.name));
    ASSERT_FALSE(corrupt_download.has_value());
    EXPECT_EQ(corrupt_download.error().code,
              kasumi::application::ErrorCode::SynchronizationFailure);
    EXPECT_FALSE(
        std::filesystem::exists(corrupt_receiver.local_dir / "file.txt"));
}

TEST(ApplicationMaintenanceContract,
     FsckWithoutSourceFailsAndPreservesHistory) {
    auto [workspace, environment, profile, remote, credentials] =
        make_maintenance_env("application-fsck-no-source", 'c');
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "file.txt", "source");
    auto opened = open_initialized_storage(profile.remote_dir);
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
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

TEST(ApplicationMaintenanceContract, ActiveBarrierBlocksSyncBeforePublication) {
    auto [workspace, environment, profile, remote, credentials] =
        make_maintenance_env("application-barrier", 'f');
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
    auto [workspace, environment, profile, remote, credentials] =
        make_maintenance_env("application-unknown-identifier", 'e');
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "file.txt", "source");
    auto opened = open_initialized_storage(profile.remote_dir);
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
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

TEST(SyncMaintenanceTest, FsckPublishesOrderedStagesAndAuthenticatedTotals) {
    auto [workspace, environment, profile, remote, credentials] =
        make_maintenance_env("fsck-progress-stages", 'd');
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "file.txt", "source");
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "remote").string());
    ASSERT_TRUE(opened.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*opened));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));

    std::vector<kasumi::application::FsckProgress> events;
    auto req = request(Operation::Fsck, environment);
    req.on_progress =
        [&](const kasumi::application::ExecutionProgress& progress) {
            if (const auto* fsck =
                    std::get_if<kasumi::application::FsckProgress>(&progress)) {
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
    const auto& completed =
        std::get<kasumi::application::FsckCompleted>(result->data);
    EXPECT_EQ(completed.checked_plaintext_bytes,
              events.back().completed_plaintext_bytes);
    EXPECT_EQ(completed.wire_download_bytes, events.back().wire_download_bytes);
    EXPECT_GT(completed.wire_download_bytes, 6U);
    EXPECT_EQ(completed.physical_objects_downloaded, 1U);
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

int run_resolve_missing_cli(std::string profile = "demo",
                            bool confirm = true,
                            bool dry_run = false,
                            std::string stdin_text = {},
                            std::string* captured_out = nullptr) {
    std::vector<std::string> args{
        "kasumi", "resolve-missing", std::move(profile)};
    if (dry_run) {
        args.emplace_back("--dry-run");
    } else if (confirm) {
        args.emplace_back("--confirm");
    }
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (auto& arg : args) {
        argv.push_back(arg.data());
    }
    std::istringstream input{std::move(stdin_text)};
    auto* previous =
        (!confirm && !dry_run) ? std::cin.rdbuf(input.rdbuf()) : nullptr;
    int exit_code = -1;
    const auto output = kasumi::test::capture_stdout([&] {
        exit_code =
            kasumi::cli::run(static_cast<int>(argv.size()), argv.data());
    });
    if (previous != nullptr) {
        std::cin.rdbuf(previous);
        std::cin.clear();
    }
    if (captured_out != nullptr) {
        *captured_out = output;
    } else if (exit_code != 0) {
        std::cerr << "CLI output (code " << exit_code << "): " << output
                  << "\n";
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
    const ExecutionEnvironment a_env{kasumi::test::workspace_path(ws, "a_app")};
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
    auto mkey =
        kasumi::test::scoped_environment_variable("KASUMI_MASTER_KEY", hex_key);
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
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

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

    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    EXPECT_FALSE(std::filesystem::exists(f.local_a / "lost.txt"));
    EXPECT_TRUE(std::filesystem::exists(f.local_a / "retained.txt"));
}

TEST(ApplicationRecoveryContract,
     ResolveMissingCliRequiresConfirmationAndSupportsDryRun) {
    auto lang = kasumi::test::scoped_environment_variable("KASUMI_LANG", "en");
    auto f = make_recovery_fixture("recovery-resolve-cli-guard");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*opened));

    kasumi::test::write_text(f.local_a / "lost.txt", "lost-cli-guard");
    kasumi::test::write_text(f.local_a / "kept.txt", "kept-cli-guard");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto lost_cid = content_id_for(f.master_hex, "lost-cli-guard");
    ASSERT_TRUE(kasumi::transport::remove(*opened, lost_cid));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));

    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());

    // --dry-run lists eligible paths without resolving them.
    std::string dry_out;
    EXPECT_EQ(run_resolve_missing_cli("demo", false, true, {}, &dry_out), 0);
    EXPECT_NE(dry_out.find("Paths eligible for logical deletion (1):"),
              std::string::npos);
    EXPECT_NE(dry_out.find("lost.txt"), std::string::npos);
    EXPECT_NE(dry_out.find(
                  "Resolve-missing dry-run completed: no deletions published."),
              std::string::npos);
    auto state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(state.has_value() && *state);
    ASSERT_EQ((*state)->pending_materializations.size(), 1U);

    // Interactive decline ('n') exits 1 and preserves pending paths.
    std::string decline_out;
    EXPECT_EQ(
        run_resolve_missing_cli("demo", false, false, "n\n", &decline_out), 1);
    EXPECT_NE(decline_out.find("lost.txt"), std::string::npos);
    EXPECT_NE(decline_out.find("Operation cancelled; pending paths preserved."),
              std::string::npos);
    state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(state.has_value() && *state &&
                (*state)->pending_materializations.size() == 1U);

    // EOF on confirmation exits 130 and preserves pending paths.
    std::string eof_out;
    EXPECT_EQ(run_resolve_missing_cli("demo", false, false, "", &eof_out), 130);
    state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(state.has_value() && *state &&
                (*state)->pending_materializations.size() == 1U);

    // Interactive confirm ('y') publishes the logical deletion.
    std::string confirm_out;
    EXPECT_EQ(
        run_resolve_missing_cli("demo", false, false, "y\n", &confirm_out), 0);
    EXPECT_NE(confirm_out.find("resolved 1 missing path"), std::string::npos);
    state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_TRUE((*state)->pending_materializations.empty());
    EXPECT_EQ(kasumi::find_row((*state)->tree, "lost.txt"), nullptr);
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
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

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

    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
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
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

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

    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));
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
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

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

    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));
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
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

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
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

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
    EXPECT_EQ(kasumi::find_row((*post_state)->tree, "lost_unrecov.txt"),
              nullptr);
    EXPECT_NE(kasumi::find_row((*post_state)->tree, "lost_recov.txt"), nullptr);
    EXPECT_TRUE(std::ranges::none_of((*post_state)->pending_materializations,
                                     [](const auto& r) {
                                         return r.path == "lost_unrecov.txt";
                                     }));
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
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

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
    const auto state =
        kasumi::state_storage::load_state(paths_b->database_path);
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

    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
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
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

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
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

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
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

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

    // Running resolve-missing must fail closed: no uploads or unrelated
    // operations!
    const auto exit_code = run_resolve_missing_cli("demo");
    EXPECT_NE(exit_code, 0);

    // Verify state was not modified / new commit with modified content was not
    // published
    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    auto post_state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(post_state.has_value() && *post_state);
    const auto* edited_row =
        kasumi::find_row((*post_state)->tree, "edited.txt");
    ASSERT_NE(edited_row, nullptr);
    EXPECT_EQ(edited_row->hash,
              kasumi::hasher::hash_string("original-content"));
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
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

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

    // Verify remote tree still has lost.txt as file, not converted to directory
    // or deleted
    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    auto post_state = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(post_state.has_value() && *post_state);
    const auto* lost_row = kasumi::find_row((*post_state)->tree, "lost.txt");
    ASSERT_NE(lost_row, nullptr);
    EXPECT_FALSE(lost_row->is_directory);
}

TEST(ApplicationRecoveryContract,
     AuthorshipFlowCoversSyncDownloadNoOpResolveMissingAndUnauthoredCommit) {
    auto f = make_recovery_fixture("authorship-sync-download-resolve");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    const auto decoded_key = kasumi::runtime::vault::decode_hex(f.master_hex);
    ASSERT_TRUE(decoded_key.has_value());

    // Machine A uploads file via Sync -> KCOM v4 Sync authorship.
    kasumi::test::write_text(f.local_a / "lost.txt", "lost-payload");
    const auto sync_a =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(sync_a.has_value()) << sync_a.error().detail;

    const auto id_a =
        kasumi::runtime::resolve_machine_identity(f.env_a.app_data_dir, false);
    ASSERT_TRUE(id_a.has_value());
    const auto paths_a =
        kasumi::runtime::resolve_profile_paths(f.env_a.app_data_dir, "demo");
    ASSERT_TRUE(paths_a.has_value());
    const auto state_a =
        kasumi::state_storage::load_state(paths_a->database_path);
    ASSERT_TRUE(state_a.has_value() && *state_a);
    const auto act_a =
        kasumi::state_storage::load_local_activity(paths_a->database_path);
    ASSERT_TRUE(act_a.has_value() && act_a->accepted_commit);
    EXPECT_EQ(act_a->accepted_commit->commit_id, (*state_a)->commit_id);
    EXPECT_EQ(act_a->accepted_commit->origin_operation,
              kasumi::history::CommitOriginOperation::Sync);
    EXPECT_EQ(act_a->accepted_commit->machine_id_hex, id_a->id_hex);
    EXPECT_EQ(act_a->accepted_commit->machine_name, id_a->name);

    // Status and Preview on fresh Machine B do NOT create machine.id.
    ASSERT_TRUE(std::filesystem::create_directories(f.local_b));
    ASSERT_FALSE(std::filesystem::exists(f.env_b.app_data_dir / "machine.id"));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Status, f.env_b)));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Preview, f.env_b)));
    EXPECT_FALSE(std::filesystem::exists(f.env_b.app_data_dir / "machine.id"));

    // Delete content so Machine B does a partial download-only sync.
    const auto lost_cid = content_id_for(f.master_hex, "lost-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, lost_cid));
    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value()) << sync_b.error().detail;

    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    const auto act_b_dl =
        kasumi::state_storage::load_local_activity(paths_b->database_path);
    ASSERT_TRUE(act_b_dl.has_value() && act_b_dl->accepted_commit);
    EXPECT_EQ(act_b_dl->accepted_commit->commit_id, (*state_a)->commit_id);
    EXPECT_EQ(act_b_dl->accepted_commit->origin_operation,
              kasumi::history::CommitOriginOperation::Sync);
    EXPECT_EQ(act_b_dl->accepted_commit->machine_id_hex, id_a->id_hex);
    EXPECT_EQ(act_b_dl->accepted_commit->machine_name, id_a->name);

    // Subsequent no-op sync on B preserves A's accepted commit authorship.
    const auto sync_b_noop =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b_noop.has_value()) << sync_b_noop.error().detail;
    const auto act_b_noop =
        kasumi::state_storage::load_local_activity(paths_b->database_path);
    ASSERT_TRUE(act_b_noop.has_value() && act_b_noop->accepted_commit);
    EXPECT_EQ(*act_b_noop->accepted_commit, *act_b_dl->accepted_commit);

    // Machine B runs resolve-missing -> publishes KCOM v4 ResolveMissing under
    // B.
    const auto id_b =
        kasumi::runtime::resolve_machine_identity(f.env_b.app_data_dir, false);
    ASSERT_TRUE(id_b.has_value());
    const auto rm = kasumi::application::execute(
        request(Operation::ResolveMissing, f.env_b));
    ASSERT_TRUE(rm.has_value()) << rm.error().detail;
    const auto act_b_rm =
        kasumi::state_storage::load_local_activity(paths_b->database_path);
    ASSERT_TRUE(act_b_rm.has_value() && act_b_rm->accepted_commit);
    EXPECT_NE(act_b_rm->accepted_commit->commit_id, (*state_a)->commit_id);
    EXPECT_EQ(act_b_rm->accepted_commit->origin_operation,
              kasumi::history::CommitOriginOperation::ResolveMissing);
    EXPECT_EQ(act_b_rm->accepted_commit->machine_id_hex, id_b->id_hex);
    EXPECT_EQ(act_b_rm->accepted_commit->machine_name, id_b->name);

    const auto obs_dir = kasumi::test::workspace_path(f.workspace, "obs");
    ASSERT_TRUE(std::filesystem::create_directories(obs_dir));
    const auto observed = kasumi::application::observation::history::observe(
        storage, *decoded_key, obs_dir, false);
    ASSERT_TRUE(observed.has_value());
    const auto head_it = std::ranges::find(observed->reachable_commits,
                                           act_b_rm->accepted_commit->commit_id,
                                           &kasumi::history::LoadedCommit::id);
    ASSERT_NE(head_it, observed->reachable_commits.end());
    EXPECT_TRUE(
        kasumi::history::has_commit_authorship(head_it->commit.authorship));
    EXPECT_EQ(head_it->commit.authorship.operation,
              kasumi::history::CommitOriginOperation::ResolveMissing);
    EXPECT_EQ(head_it->commit.authorship.machine_id, id_b->id);

    // KCOM v4 commit with undeclared authorship yields Unknown on fast-forward.
    const auto unauthored_ws =
        kasumi::test::make_temp_workspace("authorship-unauthored-kcom-v4");
    const auto seed_remote =
        kasumi::test::workspace_path(unauthored_ws, "seed_remote");
    const auto seed_local =
        kasumi::test::workspace_path(unauthored_ws, "seed_local");
    const ExecutionEnvironment seed_env{
        kasumi::test::workspace_path(unauthored_ws, "seed_app")};
    ASSERT_TRUE(std::filesystem::create_directories(seed_local));
    ASSERT_TRUE(kasumi::application::create_profile(
        seed_env,
        Profile{"demo", seed_local, seed_remote.string()},
        MasterKeyHex{f.master_hex}));
    kasumi::test::write_text(seed_local / "plain.txt", "unauthored-payload");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, seed_env)));
    const auto seed_paths =
        kasumi::runtime::resolve_profile_paths(seed_env.app_data_dir, "demo");
    ASSERT_TRUE(seed_paths.has_value());
    const auto seed_state =
        kasumi::state_storage::load_state(seed_paths->database_path);
    ASSERT_TRUE(seed_state.has_value() && *seed_state);

    const auto target_remote =
        kasumi::test::workspace_path(unauthored_ws, "remote");
    const auto target_local =
        kasumi::test::workspace_path(unauthored_ws, "local");
    ASSERT_TRUE(std::filesystem::create_directories(target_local));
    auto seed_storage_res =
        kasumi::transport::open_transport(seed_remote.string());
    ASSERT_TRUE(seed_storage_res.has_value());
    auto target_storage_res =
        kasumi::transport::open_transport(target_remote.string());
    ASSERT_TRUE(target_storage_res.has_value());
    auto& target_storage = *target_storage_res;
    ASSERT_TRUE(kasumi::transport::initialize(target_storage));
    const auto plain_cid = content_id_for(f.master_hex, "unauthored-payload");
    const auto plain_tmp =
        kasumi::test::workspace_path(unauthored_ws, "plain_content.enc");
    ASSERT_TRUE(
        kasumi::transport::get(*seed_storage_res, plain_cid, plain_tmp));
    ASSERT_TRUE(kasumi::transport::put(target_storage, plain_tmp, plain_cid));

    const auto unauthored_prepared =
        kasumi::application::sync::publication::prepare_commit(
            (*seed_state)->tree, false, 0, {}, 1700000100, *decoded_key);
    ASSERT_TRUE(unauthored_prepared.has_value());
    const auto target_layout =
        kasumi::application::history_storage::derive_remote_layout(
            *decoded_key);
    const auto stage = kasumi::test::workspace_path(unauthored_ws, "stage");
    ASSERT_TRUE(std::filesystem::create_directories(stage));
    const auto published_obj =
        kasumi::application::sync::publication::publish_commit_object(
            target_storage,
            target_layout,
            *decoded_key,
            *unauthored_prepared,
            stage);
    ASSERT_TRUE(published_obj.has_value());
    ASSERT_TRUE(kasumi::application::sync::publication::publish_head_marker(
        target_storage, target_layout, published_obj->head, stage));

    const ExecutionEnvironment target_env{
        kasumi::test::workspace_path(unauthored_ws, "app")};
    ASSERT_TRUE(kasumi::application::create_profile(
        target_env,
        Profile{"demo", target_local, target_remote.string()},
        MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, target_env)));
    EXPECT_TRUE(std::filesystem::exists(target_local / "plain.txt"));
    const auto target_paths =
        kasumi::runtime::resolve_profile_paths(target_env.app_data_dir, "demo");
    ASSERT_TRUE(target_paths.has_value());
    const auto target_act =
        kasumi::state_storage::load_local_activity(target_paths->database_path);
    ASSERT_TRUE(target_act.has_value() && target_act->accepted_commit);
    EXPECT_EQ(target_act->accepted_commit->commit_id,
              unauthored_prepared->commit_id);
    EXPECT_EQ(target_act->accepted_commit->created_at, 1700000100);
    EXPECT_EQ(target_act->accepted_commit->origin_operation,
              kasumi::history::CommitOriginOperation::Unknown);
    EXPECT_TRUE(target_act->accepted_commit->machine_id_hex.empty());
    EXPECT_TRUE(target_act->accepted_commit->machine_name.empty());

    // Pure download-only sync records SucceededDownloadedOnly and sets
    // last_complete_sync.
    const auto target_act_summary =
        kasumi::application::inspect_profile_activity(target_env, "demo");
    ASSERT_TRUE(target_act_summary.last_complete_sync.has_value());
    EXPECT_EQ(
        target_act_summary.last_complete_sync->status,
        kasumi::application::ProfileExecutionStatus::SucceededDownloadedOnly);
}

TEST(
    ApplicationMaintenanceContract,
    MaintenancePublishesRemoteActivityGcRetentionWorksAndInvalidActivityFailsClosed) {
    auto [workspace, environment, profile, remote, credentials] =
        make_maintenance_env("activity-maintenance-gc-retention", '8');
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    kasumi::test::write_text(profile.local_dir / "doc.txt", "v1");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));

    // 1. Fsck publishes Succeeded record visible via remote summary.
    const auto fsck_ok =
        kasumi::application::execute(request(Operation::Fsck, environment));
    ASSERT_TRUE(fsck_ok.has_value()) << fsck_ok.error().detail;

    // 2. Establish writer & remove it + remove absent barrier -> both publish.
    auto opened = open_initialized_storage(profile.remote_dir);
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    const auto key_bytes =
        *kasumi::runtime::vault::decode_hex(std::string(64, '8'));
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(key_bytes);
    const auto wr_stage = kasumi::test::workspace_path(workspace, "wr");
    ASSERT_TRUE(std::filesystem::create_directories(wr_stage));
    auto writer = protocol::register_writer(storage, layout, wr_stage);
    ASSERT_TRUE(writer.has_value());
    const auto writer_id = writer->identifier;
    writer->storage = nullptr;
    auto rw_req = request(Operation::RemoveWriter, environment);
    rw_req.request.writer_identifier = writer_id;
    ASSERT_TRUE(kasumi::application::execute(rw_req));

    auto rb_req = request(Operation::RemoveBarrier, environment);
    rb_req.request.confirm_abandoned = true;
    ASSERT_TRUE(kasumi::application::execute(rb_req));

    // 3. Seed old KACT v1 records (> age hours + > depth) and keep newest
    // Succeeded Fsck record, then run GC -> old non-protected records pruned,
    // newest Succeeded per (machine, op) + depth retained.
    const auto machine = kasumi::runtime::resolve_machine_identity(
        environment.app_data_dir, false);
    ASSERT_TRUE(machine.has_value());
    const auto old_stage = kasumi::test::workspace_path(workspace, "old_act");
    ASSERT_TRUE(std::filesystem::create_directories(old_stage));
    for (int i = 1; i <= 6; ++i) {
        const std::string hex_suffix =
            "0000000000000000000000000000000" + std::to_string(i);
        kasumi::application::history_storage::activity::ActivityRecord old_rec{
            .event_id = hex_suffix,
            .operation = kasumi::application::history_storage::activity::
                ActivityOperation::Fsck,
            .outcome = kasumi::application::history_storage::activity::
                ActivityOutcome::IssuesFound,
            .machine_id = machine->id,
            .machine_name = machine->name,
            .started_at = 100000 + i,
            .finished_at = 100010 + i,
        };
        ASSERT_TRUE(kasumi::application::history_storage::activity::publish(
            storage, layout, key_bytes, old_rec, old_stage));
    }

    const auto gc_res = kasumi::application::execute(
        request(Operation::GarbageCollect, environment));
    ASSERT_TRUE(gc_res.has_value()) << gc_res.error().detail;

    // 4. Corrupt an object under activity/v1/ -> GC fails closed before
    // deleting anything and remote objects remain intact.
    const auto bad_file = kasumi::test::workspace_path(workspace, "bad_act");
    kasumi::test::write_text(bad_file, "corrupt-activity-payload");
    const auto bad_id = layout.activity_prefix + "bad-activity-object";
    ASSERT_TRUE(kasumi::transport::put(storage, bad_file, bad_id));
    const auto listing_before_fail = kasumi::transport::list(storage);
    ASSERT_TRUE(listing_before_fail.has_value());
    const auto gc_fail = kasumi::application::execute(
        request(Operation::GarbageCollect, environment));
    ASSERT_FALSE(gc_fail.has_value());
    EXPECT_EQ(gc_fail.error().code,
              kasumi::application::ErrorCode::GarbageCollectionFailure);
    for (const auto& obj : *listing_before_fail) {
        if (!kasumi::application::history_storage::is_activity_object(layout,
                                                                      obj)) {
            EXPECT_EQ(kasumi::transport::presence(storage, obj).value(),
                      kasumi::transport::Presence::Present);
        }
    }
    ASSERT_TRUE(kasumi::transport::remove(storage, bad_id));

    // 5. Inspection from second machine sees remote activities cleanly without
    // modifying anything.
    const auto summary = kasumi::application::inspect(
        {kasumi::application::InspectionRequest{
             .operation =
                 kasumi::application::InspectionOperation::RemoteSummary,
             .profile_name = "demo"},
         credentials,
         environment});
    ASSERT_TRUE(summary.has_value()) << summary.error().detail;
    const auto& sum_rep =
        std::get<kasumi::application::RemoteSummaryReport>(summary->payload);
    EXPECT_EQ(sum_rep.invalid_activity_count, 0U);
    EXPECT_FALSE(sum_rep.recent_activities.empty());
}

} // namespace
