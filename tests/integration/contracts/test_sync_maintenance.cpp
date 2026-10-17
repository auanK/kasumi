#include "application/execute.hpp"
#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/history.hpp"
#include "application/profile.hpp"
#include "cli/app.hpp"
#include "core/hasher.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/provider_scenarios.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "runtime/paths.hpp"
#include "runtime/vault.hpp"
#include "application/observation/state.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/reobservation.hpp"
#include "application/use_cases/context.hpp"
#include "core/reconciliation/plan.hpp"
#include "platform/metadata.hpp"
#include "platform/perf_trace.hpp"
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

namespace kasumi::application::detail {
std::expected<Response, Error> run_sync(OperationContext& context);
} // namespace kasumi::application::detail

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

template <typename Hook>
std::expected<kasumi::application::Response, kasumi::application::Error>
execute_sync_with_hook(kasumi::application::ExecutionInput input, Hook&& hook) {
    kasumi::application::detail::OperationContext context{};
    auto prepared = kasumi::application::detail::prepare_operation(input, context);
    if (!prepared) {
        return std::unexpected(prepared.error());
    }
    hook(context.storage);
    auto result = kasumi::application::detail::run_sync(context);
    context.storage = {};
    kasumi::application::detail::wipe_operation(context);
    return result;
}

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
     PublicSyncPreviewStatusAndFsckRemainAvailable) {
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
    ASSERT_TRUE(kasumi::state_storage::initialize(paths->database_path));
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

    const auto trusted_no_op =
        kasumi::application::execute(request(Operation::Sync, environment));
    ASSERT_TRUE(trusted_no_op.has_value()) << trusted_no_op.error().detail;

    const auto identifier = content_identifier(storage);
    ASSERT_FALSE(identifier.empty());
    ASSERT_EQ(kasumi::transport::remove(storage, identifier).value(),
              kasumi::transport::Removal::Removed);
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

TEST(ApplicationMaintenanceContract,
     GarbageCollectPropagatesCategoryCountsToApplicationResult) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-gc-category-counts");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    const std::string master_hex(64, '7');
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{master_hex}));
    kasumi::test::write_text(profile.local_dir / "file.txt", "live-payload");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, environment)));

    auto opened = kasumi::transport::open_transport(profile.remote_dir);
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    const auto key = kasumi::runtime::vault::decode_hex(master_hex);
    ASSERT_TRUE(key.has_value());

    // Add 1 orphan content object and 1 dispensable commit variant.
    const auto orphan_id = kasumi::crypto::content_identifier(
        *key, kasumi::hasher::hash_string("orphan-payload"));
    const auto plain = kasumi::test::workspace_path(workspace, "orphan.plain");
    const auto enc = kasumi::test::workspace_path(workspace, "orphan.enc");
    kasumi::test::write_text(plain, "orphan-payload");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, enc, *key));
    ASSERT_TRUE(kasumi::transport::put(storage, enc, orphan_id));

    const auto history =
        kasumi::application::history_storage::inventory_reachability(
            storage, *key, environment.app_data_dir);
    ASSERT_TRUE(history.has_value()) << history.error().detail;
    ASSERT_EQ(history->logical_heads.size(), 1U);
    const auto loaded = kasumi::application::history_storage::load_history(
        storage, *key, environment.app_data_dir);
    ASSERT_TRUE(loaded.has_value()) << loaded.error().detail;
    ASSERT_FALSE(loaded->commits.empty());
    const auto canonical =
        kasumi::history::serialize(loaded->commits.back().commit).value();
    const auto variant_plain =
        kasumi::test::workspace_path(workspace, "variant.plain");
    const auto variant_enc =
        kasumi::test::workspace_path(workspace, "variant.enc");
    kasumi::test::write_binary(variant_plain,
                               std::as_bytes(std::span{canonical}));
    ASSERT_TRUE(kasumi::crypto::encrypt_file(variant_plain,
                                             variant_enc,
                                             *key,
                                             kasumi::crypto::FilePurpose::History));
    const auto variant_hash =
        kasumi::crypto::content::hash_file(variant_enc).value();
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(*key);
    const kasumi::application::history_storage::HeadReference extra_variant{
        .commit_id = kasumi::crypto::commit_identifier(*key, canonical),
        .ciphertext_id = kasumi::hash_hex(variant_hash),
    };
    ASSERT_TRUE(kasumi::transport::put(
        storage,
        variant_enc,
        kasumi::application::history_storage::commit_object(layout,
                                                            extra_variant)));

    const auto gc = kasumi::application::execute(
        request(Operation::GarbageCollect, environment));
    ASSERT_TRUE(gc.has_value()) << gc.error().detail;
    const auto* completed =
        std::get_if<kasumi::application::GarbageCollectCompleted>(&gc->data);
    ASSERT_NE(completed, nullptr);
    EXPECT_EQ(completed->content_candidate_objects, 1U);
    EXPECT_EQ(completed->commit_variant_candidate_objects, 1U);
    EXPECT_EQ(completed->candidate_objects, 2U);
    EXPECT_EQ(completed->candidate_objects,
              completed->content_candidate_objects +
                  completed->commit_variant_candidate_objects);
    EXPECT_EQ(completed->directly_removed_objects, 1U);
    EXPECT_EQ(completed->quarantined_objects, 1U);
}

TEST(RemoteContentRecoveryContract, NoOpHealthyDoesNotModifyStorageOrState) {
    auto f = make_recovery_fixture("recovery-noop-healthy");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));

    kasumi::test::write_text(f.local_a / "healthy.txt", "healthy-payload");
    const auto initial_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(initial_sync.has_value()) << initial_sync.error().detail;

    const auto paths_a =
        kasumi::runtime::resolve_profile_paths(f.env_a.app_data_dir, "demo");
    ASSERT_TRUE(paths_a.has_value());
    const auto db_before = kasumi::test::read_binary(paths_a->database_path);
    const auto state_before =
        kasumi::state_storage::load_state(paths_a->database_path);
    ASSERT_TRUE(state_before.has_value() && *state_before);

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto list_before = kasumi::transport::list(*opened);
    ASSERT_TRUE(list_before.has_value());
    std::ranges::sort(*list_before);

    kasumi::platform::perf_trace::force_enable(true);
    const auto noop_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    const auto content_list_count =
        kasumi::platform::perf_trace::get_count("sync content listing");
    const auto transport_list_count =
        kasumi::platform::perf_trace::get_count("transport list");
    const auto get_content_count =
        kasumi::platform::perf_trace::get_count("rc/get_content");
    const auto put_commit_count =
        kasumi::platform::perf_trace::get_count("rc/put_commit");
    const auto presence_probe_count =
        kasumi::platform::perf_trace::get_count("sync content presence probe");
    kasumi::platform::perf_trace::force_enable(false);

    ASSERT_TRUE(noop_sync.has_value()) << noop_sync.error().detail;
    const auto* comp =
        std::get_if<kasumi::application::SyncCompleted>(&noop_sync->data);
    ASSERT_NE(comp, nullptr);
    EXPECT_GE(content_list_count, 1U);
    EXPECT_GE(transport_list_count, 1U);
    EXPECT_EQ(presence_probe_count, 0U);
    EXPECT_EQ(get_content_count, 0U);
    EXPECT_EQ(put_commit_count, 0U);
    EXPECT_EQ(comp->uploaded, 0U);
    EXPECT_EQ(comp->downloaded, 0U);
    EXPECT_EQ(comp->removed, 0U);
    EXPECT_FALSE(comp->published);
    EXPECT_EQ(comp->pending, 0U);
    EXPECT_FALSE(comp->partial);

    const auto db_after = kasumi::test::read_binary(paths_a->database_path);
    EXPECT_EQ(db_before, db_after);
    const auto state_after =
        kasumi::state_storage::load_state(paths_a->database_path);
    ASSERT_TRUE(state_after.has_value() && *state_after);
    EXPECT_EQ((*state_before)->commit_id, (*state_after)->commit_id);
    EXPECT_EQ((*state_before)->height, (*state_after)->height);

    auto list_after = kasumi::transport::list(*opened);
    ASSERT_TRUE(list_after.has_value());
    std::ranges::sort(*list_after);
    EXPECT_EQ(*list_before, *list_after);
}

TEST(RemoteContentRecoveryContract,
     NoOpWithMissingRemoteContentRepairsStorageWithoutNewCommit) {
    auto f = make_recovery_fixture("recovery-noop-repair");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "doc.txt", "doc-content-to-repair");
    const auto initial_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(initial_sync.has_value());

    const auto cid = content_id_for(f.master_hex, "doc-content-to-repair");
    ASSERT_FALSE(cid.empty());
    ASSERT_EQ(kasumi::transport::presence(storage, cid).value(),
              kasumi::transport::Presence::Present);

    // Physically delete the remote ciphertext
    ASSERT_TRUE(kasumi::transport::remove(storage, cid));
    ASSERT_EQ(kasumi::transport::presence(storage, cid).value(),
              kasumi::transport::Presence::Absent);

    // Local file is intact and unchanged
    EXPECT_EQ(kasumi::test::read_text(f.local_a / "doc.txt"),
              "doc-content-to-repair");

    // Sync on device with intact local copy must detect missing content and repair it
    const auto repair_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(repair_sync.has_value()) << repair_sync.error().detail;
    const auto* comp =
        std::get_if<kasumi::application::SyncCompleted>(&repair_sync->data);
    ASSERT_NE(comp, nullptr);
    EXPECT_EQ(comp->uploaded, 1U);
    EXPECT_FALSE(comp->published); // Must NOT publish a new commit!
    EXPECT_EQ(comp->pending, 0U);

    // Remote ciphertext is restored!
    EXPECT_EQ(kasumi::transport::presence(storage, cid).value(),
              kasumi::transport::Presence::Present);
    EXPECT_EQ(kasumi::test::read_text(f.local_a / "doc.txt"),
              "doc-content-to-repair");
}

TEST(RemoteContentRecoveryContract,
     MissingRemoteContentWithoutLocalCopyPreservesPendingMaterialization) {
    auto f = make_recovery_fixture("recovery-missing-no-local");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "unobtainable.txt", "payload-x");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto cid = content_id_for(f.master_hex, "payload-x");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid));

    // Device B has no local copy of unobtainable.txt
    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value()) << sync_b.error().detail;
    const auto* comp =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(comp, nullptr);
    EXPECT_TRUE(comp->partial);
    EXPECT_GE(comp->pending, 1U);
    EXPECT_FALSE(std::filesystem::exists(f.local_b / "unobtainable.txt"));

    // Check DB state preserves pending materialization
    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    auto state_b = kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(state_b.has_value() && *state_b);
    EXPECT_NE(kasumi::find_row((*state_b)->tree, "unobtainable.txt"), nullptr);
    EXPECT_EQ((*state_b)->pending_materializations.size(), 1U);
}

TEST(RemoteContentRecoveryContract, MultiDeviceRecoveryAndConvergence) {
    auto f = make_recovery_fixture("recovery-multi-device");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    // 1. A publishes shared.txt
    kasumi::test::write_text(f.local_a / "shared.txt", "convergence-payload");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

    // 2. Remote payload is deleted physically (lost on storage)
    const auto cid = content_id_for(f.master_hex, "convergence-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid));
    ASSERT_EQ(kasumi::transport::presence(storage, cid).value(),
              kasumi::transport::Presence::Absent);

    // 3. B tries to sync -> payload missing remotely, B preserves pending materialization
    const auto b_sync_pending =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(b_sync_pending.has_value());
    const auto* comp_b1 =
        std::get_if<kasumi::application::SyncCompleted>(&b_sync_pending->data);
    ASSERT_NE(comp_b1, nullptr);
    EXPECT_TRUE(comp_b1->partial);
    EXPECT_GE(comp_b1->pending, 1U);
    EXPECT_FALSE(std::filesystem::exists(f.local_b / "shared.txt"));

    // 4. A (has intact local copy) syncs -> repairs remote storage without new commit
    const auto a_repair_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(a_repair_sync.has_value());
    const auto* comp_a =
        std::get_if<kasumi::application::SyncCompleted>(&a_repair_sync->data);
    ASSERT_NE(comp_a, nullptr);
    EXPECT_EQ(comp_a->uploaded, 1U);
    EXPECT_FALSE(comp_a->published);
    EXPECT_EQ(kasumi::transport::presence(storage, cid).value(),
              kasumi::transport::Presence::Present);

    // 5. B syncs again -> payload is now available, B downloads and converges!
    const auto b_converge_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(b_converge_sync.has_value());
    const auto* comp_b2 =
        std::get_if<kasumi::application::SyncCompleted>(&b_converge_sync->data);
    ASSERT_NE(comp_b2, nullptr);
    EXPECT_FALSE(comp_b2->partial);
    EXPECT_EQ(comp_b2->downloaded, 1U);
    EXPECT_EQ(kasumi::test::read_text(f.local_b / "shared.txt"),
              "convergence-payload");
}

TEST(RemoteContentRecoveryContract,
     IntentionalDeletionNotResurrectedByPhysicalAbsence) {
    auto f = make_recovery_fixture("recovery-intentional-deletion");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "to_delete.txt", "payload-del");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto cid = content_id_for(f.master_hex, "payload-del");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid));

    // Intentionally delete file locally
    std::filesystem::remove(f.local_a / "to_delete.txt");

    // Sync must publish deletion, NOT attempt repair upload
    const auto del_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(del_sync.has_value());
    const auto* comp =
        std::get_if<kasumi::application::SyncCompleted>(&del_sync->data);
    ASSERT_NE(comp, nullptr);
    EXPECT_EQ(comp->uploaded, 0U);
    EXPECT_EQ(comp->removed, 1U);
    EXPECT_TRUE(comp->published);
    EXPECT_FALSE(std::filesystem::exists(f.local_a / "to_delete.txt"));
}

TEST(RemoteContentRecoveryContract, ListingErrorDuringSyncFailsClosed) {
    auto f = make_recovery_fixture("recovery-listing-error");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "file.txt", "file-content");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto key = kasumi::runtime::vault::decode_hex(f.master_hex);
    ASSERT_TRUE(key.has_value());

    kasumi::reconciliation::Input input;
    input.storage.history_present = true;
    kasumi::reconciliation::Result result;
    result.candidate_shared_tree.rows.push_back(
        kasumi::NodeRow{.path = "file.txt",
                        .hash = kasumi::hasher::hash_string("file-content"),
                        .size = 12,
                        .is_directory = false});

    // Inject Io error on list
    storage.storage.list = [](void*) -> kasumi::transport::ListingResult {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io,
            .message = "simulated remote listing I/O error"});
    };

    auto availability =
        kasumi::application::sync::coordinator::reobservation::
            observe_content_availability(input, result, storage, *key);
    ASSERT_FALSE(availability.has_value());
    EXPECT_EQ(
        availability.error().code,
        kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
    EXPECT_TRUE(input.known_missing_content_objects.empty());
}

TEST(RemoteContentRecoveryContract, InconclusivePresenceFailsClosed) {
    auto f = make_recovery_fixture("recovery-presence-inconclusive");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    const auto key = kasumi::runtime::vault::decode_hex(f.master_hex);
    ASSERT_TRUE(key.has_value());

    kasumi::reconciliation::Input input;
    input.storage.history_present = true;
    kasumi::reconciliation::Result result;
    const auto hash = kasumi::hasher::hash_string("test-data");
    result.candidate_shared_tree.rows.push_back(
        kasumi::NodeRow{.path = "test.txt",
                        .hash = hash,
                        .size = 9,
                        .is_directory = false});

    // List returns empty list (test-data is not in listing)
    storage.storage.list = [](void*) -> kasumi::transport::ListingResult {
        return std::vector<std::string>{};
    };
    // Presence probe returns I/O failure (inconclusive)
    storage.storage.control_read_batch = nullptr;
    storage.storage.presence =
        [](void*, std::string_view) -> kasumi::transport::PresenceResult {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io,
            .message = "simulated presence probe I/O error"});
    };

    auto availability =
        kasumi::application::sync::coordinator::reobservation::
            observe_content_availability(input, result, storage, *key);
    ASSERT_FALSE(availability.has_value());
    EXPECT_EQ(
        availability.error().code,
        kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
    EXPECT_TRUE(input.known_missing_content_objects.empty());
}

TEST(RemoteContentRecoveryContract,
     TransportErrorSemanticsInContentAvailability) {
    auto f = make_recovery_fixture("recovery-transport-error-semantics");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    const auto key = kasumi::runtime::vault::decode_hex(f.master_hex);
    ASSERT_TRUE(key.has_value());

    const auto hash = kasumi::hasher::hash_string("semantics-data");
    const auto cid = kasumi::crypto::content_identifier(*key, hash);
    kasumi::reconciliation::Result result;
    result.candidate_shared_tree.rows.push_back(
        kasumi::NodeRow{.path = "test.txt",
                        .hash = hash,
                        .size = 14,
                        .is_directory = false});

    // 1. StorageNotFound on LIST when history_present == false is valid (no
    // remote history exists yet).
    {
        kasumi::reconciliation::Input input;
        input.storage.history_present = false;
        storage.storage.list = [](void*) -> kasumi::transport::ListingResult {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::StorageNotFound,
                .message = "remote root not created yet"});
        };
        auto availability =
            kasumi::application::sync::coordinator::reobservation::
                observe_content_availability(input, result, storage, *key);
        EXPECT_TRUE(availability.has_value());
        EXPECT_TRUE(input.known_missing_content_objects.empty());
    }

    // 2. StorageNotFound on LIST when history_present == true MUST fail closed
    // (remote namespace disappeared after history was observed).
    {
        kasumi::reconciliation::Input input;
        input.storage.history_present = true;
        storage.storage.list = [](void*) -> kasumi::transport::ListingResult {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::StorageNotFound,
                .message = "remote root disappeared"});
        };
        auto availability =
            kasumi::application::sync::coordinator::reobservation::
                observe_content_availability(input, result, storage, *key);
        ASSERT_FALSE(availability.has_value());
        EXPECT_EQ(availability.error().code,
                  kasumi::application::sync::coordinator::ErrorCode::
                      ObservationFailure);
        EXPECT_TRUE(input.known_missing_content_objects.empty());
    }

    // 3. PermissionDenied (authentication/authorization error) on LIST fails closed.
    {
        kasumi::reconciliation::Input input;
        input.storage.history_present = true;
        storage.storage.list = [](void*) -> kasumi::transport::ListingResult {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::PermissionDenied,
                .message = "simulated auth failure"});
        };
        auto availability =
            kasumi::application::sync::coordinator::reobservation::
                observe_content_availability(input, result, storage, *key);
        ASSERT_FALSE(availability.has_value());
        EXPECT_EQ(availability.error().code,
                  kasumi::application::sync::coordinator::ErrorCode::
                      ObservationFailure);
    }

    // 4. Unconfirmed absence from LIST without any presence probe capability
    // (both control_read_batch and presence are nullptr) MUST fail closed.
    {
        kasumi::reconciliation::Input input;
        input.storage.history_present = true;
        storage.storage.list = [](void*) -> kasumi::transport::ListingResult {
            return std::vector<std::string>{};
        };
        storage.storage.control_read_batch = nullptr;
        storage.storage.presence = nullptr;
        auto availability =
            kasumi::application::sync::coordinator::reobservation::
                observe_content_availability(input, result, storage, *key);
        ASSERT_FALSE(availability.has_value());
        EXPECT_EQ(availability.error().code,
                  kasumi::application::sync::coordinator::ErrorCode::
                      ObservationFailure);
        EXPECT_TRUE(input.known_missing_content_objects.empty());
    }

    // 5. Object absent from LIST (eventual consistency) but Present in probe
    // is NOT marked missing.
    {
        kasumi::reconciliation::Input input;
        input.storage.history_present = true;
        storage.storage.list = [](void*) -> kasumi::transport::ListingResult {
            return std::vector<std::string>{};
        };
        storage.storage.control_read_batch = nullptr;
        storage.storage.presence =
            [](void*, std::string_view) -> kasumi::transport::PresenceResult {
            return kasumi::transport::Presence::Present;
        };
        auto availability =
            kasumi::application::sync::coordinator::reobservation::
                observe_content_availability(input, result, storage, *key);
        ASSERT_TRUE(availability.has_value()) << availability.error().detail;
        EXPECT_TRUE(input.known_missing_content_objects.empty());
    }

    // 6. Valid empty listing confirmed by Presence::Absent marks object missing.
    {
        kasumi::reconciliation::Input input;
        input.storage.history_present = true;
        storage.storage.list = [](void*) -> kasumi::transport::ListingResult {
            return std::vector<std::string>{};
        };
        storage.storage.control_read_batch = nullptr;
        storage.storage.presence =
            [](void*, std::string_view) -> kasumi::transport::PresenceResult {
            return kasumi::transport::Presence::Absent;
        };
        auto availability =
            kasumi::application::sync::coordinator::reobservation::
                observe_content_availability(input, result, storage, *key);
        ASSERT_TRUE(availability.has_value()) << availability.error().detail;
        EXPECT_TRUE(input.known_missing_content_objects.contains(hash));
    }

    // 7. Intact listing containing cid succeeds without calling presence probe.
    {
        kasumi::reconciliation::Input input;
        input.storage.history_present = true;
        static std::string s_cid;
        s_cid = cid;
        storage.storage.list = [](void*) -> kasumi::transport::ListingResult {
            return std::vector<std::string>{s_cid};
        };
        storage.storage.control_read_batch = nullptr;
        storage.storage.presence =
            [](void*, std::string_view) -> kasumi::transport::PresenceResult {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Io,
                .message = "presence should not be called when listed"});
        };
        auto availability =
            kasumi::application::sync::coordinator::reobservation::
                observe_content_availability(input, result, storage, *key);
        ASSERT_TRUE(availability.has_value()) << availability.error().detail;
        EXPECT_TRUE(input.known_missing_content_objects.empty());
    }
}

TEST(RemoteContentRecoveryContract,
     KnownMissingContentObjectsRemainStableAcrossReplanningAndClearWhenRestored) {
    auto f = make_recovery_fixture("recovery-known-missing-stability");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    const auto key = kasumi::runtime::vault::decode_hex(f.master_hex);
    ASSERT_TRUE(key.has_value());

    const auto h_base = kasumi::hasher::hash_string("base-content");
    const auto h_remote = kasumi::hasher::hash_string("remote-missing-conflict");
    const auto h_local = kasumi::hasher::hash_string("local-winner-conflict");
    const auto cid_local = kasumi::crypto::content_identifier(*key, h_local);
    const auto cid_remote = kasumi::crypto::content_identifier(*key, h_remote);

    // Store only cid_local on remote storage; cid_remote is physically absent.
    const auto local_blob = kasumi::test::workspace_path(f.workspace, "local.blob");
    kasumi::test::write_text(local_blob, "local-winner-conflict");
    ASSERT_TRUE(kasumi::transport::put(storage, local_blob, cid_local));

    const auto head_id = std::string(64, 'a');
    kasumi::reconciliation::Input input;
    input.storage.history_present = true;
    input.storage.logical_heads = {head_id};
    input.storage.marked_heads = {head_id};
    input.storage.reachable_commit_ids = {head_id};
    input.base_state_present = true;
    input.base_commit_id = head_id;
    input.local_generation = 0;
    input.storage.generation = 0;

    input.base_tree = kasumi::Snapshot{
        .rows = {
            kasumi::NodeRow{.path = "", .is_directory = true},
            kasumi::NodeRow{
                .path = "conflict.txt", .hash = h_base, .size = 12, .mtime = 10},
        }};
    kasumi::finalize_snapshot(input.base_tree);

    input.storage.tree = kasumi::Snapshot{
        .rows = {
            kasumi::NodeRow{.path = "", .is_directory = true},
            kasumi::NodeRow{.path = "conflict.txt",
                            .hash = h_remote,
                            .size = 23,
                            .mtime = 20},
        }};
    kasumi::finalize_snapshot(input.storage.tree);
    input.storage.reachable_commits = {
        {.id = head_id, .commit = {.height = 0, .tree = input.base_tree}}};

    input.local_tree = kasumi::Snapshot{
        .rows = {
            kasumi::NodeRow{.path = "", .is_directory = true},
            kasumi::NodeRow{.path = "conflict.txt",
                            .hash = h_local,
                            .size = 21,
                            .mtime = 30},
        }};
    kasumi::finalize_snapshot(input.local_tree);

    // Pass 1: initial reconciliation (unmasked) and availability check.
    auto pass1 = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(pass1.has_value()) << pass1.error().detail;
    ASSERT_TRUE(kasumi::application::sync::coordinator::reobservation::
                    observe_content_availability(input, *pass1, storage, *key));
    EXPECT_TRUE(input.known_missing_content_objects.contains(h_remote));

    // Pass 2: replanning (as happens during verify_destructive_local_operations
    // or repeated reobservation passes) must NOT lose h_remote!
    auto pass2 = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(pass2.has_value()) << pass2.error().detail;
    ASSERT_TRUE(kasumi::application::sync::coordinator::reobservation::
                    observe_content_availability(input, *pass2, storage, *key));
    EXPECT_TRUE(input.known_missing_content_objects.contains(h_remote));

    // Pass 3: when cid_remote is restored on remote storage, reobservation
    // clears the stale missing entry!
    ASSERT_TRUE(kasumi::transport::put(storage, local_blob, cid_remote));
    ASSERT_TRUE(kasumi::application::sync::coordinator::reobservation::
                    observe_content_availability(input, *pass2, storage, *key));
    EXPECT_FALSE(input.known_missing_content_objects.contains(h_remote));
}

TEST(RemoteContentRecoveryContract,
     IncompatibleLocalHashRejectsCorruptedRepair) {
    auto f = make_recovery_fixture("recovery-corrupt-local-hash");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "file.txt", "good-payload");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto good_cid = content_id_for(f.master_hex, "good-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, good_cid));

    // Tamper with local file: change contents to bad payload
    kasumi::test::write_text(f.local_a / "file.txt", "tampered-bad-payload");

    // Sync: local file has changed, so local hash does not match original good-payload.
    // Kasumi must NOT upload "tampered-bad-payload" under good_cid!
    const auto sync_tampered =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(sync_tampered.has_value());

    // good_cid must NOT have been restored by tampered bytes!
    EXPECT_EQ(kasumi::transport::presence(storage, good_cid).value(),
              kasumi::transport::Presence::Absent);
}

TEST(RemoteContentRecoveryContract, FailureDuringRepairUploadRetriesSafely) {
    auto f = make_recovery_fixture("recovery-upload-failure-retry");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "retry.txt", "payload-to-retry");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto paths_a =
        kasumi::runtime::resolve_profile_paths(f.env_a.app_data_dir, "demo");
    ASSERT_TRUE(paths_a.has_value());
    const auto state_before =
        kasumi::state_storage::load_state(paths_a->database_path);
    ASSERT_TRUE(state_before.has_value() && *state_before);

    const auto cid = content_id_for(f.master_hex, "payload-to-retry");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid));

    static decltype(storage.storage.put) s_real_put = nullptr;
    static decltype(storage.storage.get) s_real_get = nullptr;
    static std::string s_cid;
    s_cid = cid;

    // 1. Fail during PUT of repair upload: Sync fails closed, remote object
    // remains Absent, local file and commit_id remain intact.
    const auto sync_fail = execute_sync_with_hook(
        request(Operation::Sync, f.env_a),
        [](kasumi::transport::Transport& hooked) {
            s_real_put = hooked.storage.put;
            hooked.storage.put_batch = nullptr;
            hooked.storage.put = [](void* state,
                                    const std::filesystem::path& src,
                                    std::string_view id) -> kasumi::transport::Result {
                if (id == s_cid) {
                    return std::unexpected(kasumi::transport::Error{
                        .code = kasumi::transport::ErrorCode::Io,
                        .message = "simulated repair upload I/O failure"});
                }
                return s_real_put(state, src, id);
            };
        });
    ASSERT_FALSE(sync_fail.has_value());
    EXPECT_EQ(kasumi::transport::presence(storage, cid).value(),
              kasumi::transport::Presence::Absent);
    EXPECT_EQ(kasumi::test::read_text(f.local_a / "retry.txt"),
              "payload-to-retry");

    // 2. Fail after remote write of repair upload, before journal completion:
    // underlying PUT writes cid to remote storage and returns ErrorCode::Io,
    // and readback GET also returns ErrorCode::Io so the effect is unknown and
    // the journal is preserved for recovery.
    const auto sync_ambiguous = execute_sync_with_hook(
        request(Operation::Sync, f.env_a),
        [](kasumi::transport::Transport& hooked) {
            s_real_put = hooked.storage.put;
            s_real_get = hooked.storage.get;
            hooked.storage.put_batch = nullptr;
            hooked.storage.put = [](void* state,
                                    const std::filesystem::path& src,
                                    std::string_view id) -> kasumi::transport::Result {
                auto res = s_real_put(state, src, id);
                if (!res || id != s_cid) {
                    return res;
                }
                return std::unexpected(kasumi::transport::Error{
                    .code = kasumi::transport::ErrorCode::Io,
                    .message = "simulated failure after remote write before journal completion"});
            };
            hooked.storage.get = [](void* state,
                                    std::string_view id,
                                    const std::filesystem::path& dst) -> kasumi::transport::Result {
                if (id == s_cid) {
                    return std::unexpected(kasumi::transport::Error{
                        .code = kasumi::transport::ErrorCode::Io,
                        .message = "simulated readback failure leaving journal active"});
                }
                return s_real_get(state, id, dst);
            };
        });
    ASSERT_FALSE(sync_ambiguous.has_value());
    // Remote object was physically written before the error, and journal holds
    // the interrupted entry.
    EXPECT_EQ(kasumi::transport::presence(storage, cid).value(),
              kasumi::transport::Presence::Present);
    const auto j_paths =
        kasumi::application::sync::journal::make_paths(paths_a->profile_dir);
    ASSERT_TRUE(j_paths.has_value());
    EXPECT_TRUE(std::filesystem::exists(j_paths->final_path));

    // Subsequent Sync recovers the interrupted journal and finishes cleanly
    // without publishing a duplicate commit.
    const auto sync_ok =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(sync_ok.has_value()) << sync_ok.error().detail;
    const auto* comp_ok =
        std::get_if<kasumi::application::SyncCompleted>(&sync_ok->data);
    ASSERT_NE(comp_ok, nullptr);
    EXPECT_FALSE(comp_ok->published);
    EXPECT_EQ(kasumi::transport::presence(storage, cid).value(),
              kasumi::transport::Presence::Present);
    EXPECT_FALSE(std::filesystem::exists(j_paths->final_path));
    const auto state_after =
        kasumi::state_storage::load_state(paths_a->database_path);
    ASSERT_TRUE(state_after.has_value() && *state_after);
    EXPECT_EQ((*state_before)->commit_id, (*state_after)->commit_id);

    // 3. Shared object upload succeeds, but commit publication fails; retry
    // recovers and publishes both logical paths cleanly.
    kasumi::test::write_text(f.local_a / "pub1.txt", "shared-pub-payload");
    kasumi::test::write_text(f.local_a / "pub2.txt", "shared-pub-payload");
    static std::string s_pub_cid;
    static bool s_pub_uploaded = false;
    s_pub_cid = content_id_for(f.master_hex, "shared-pub-payload");
    s_pub_uploaded = false;
    const auto sync_pub_fail = execute_sync_with_hook(
        request(Operation::Sync, f.env_a),
        [](kasumi::transport::Transport& hooked) {
            s_real_put = hooked.storage.put;
            hooked.storage.put_batch = nullptr;
            hooked.storage.put = [](void* state,
                                    const std::filesystem::path& src,
                                    std::string_view id) -> kasumi::transport::Result {
                if (id == s_pub_cid) {
                    s_pub_uploaded = true;
                    return s_real_put(state, src, id);
                }
                if (s_pub_uploaded) {
                    return std::unexpected(kasumi::transport::Error{
                        .code = kasumi::transport::ErrorCode::Io,
                        .message = "simulated commit publication failure"});
                }
                return s_real_put(state, src, id);
            };
        });
    ASSERT_FALSE(sync_pub_fail.has_value());

    const auto sync_pub_retry =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(sync_pub_retry.has_value()) << sync_pub_retry.error().detail;
    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value()) << sync_b.error().detail;
    EXPECT_EQ(kasumi::test::read_text(f.local_b / "pub1.txt"),
              "shared-pub-payload");
    EXPECT_EQ(kasumi::test::read_text(f.local_b / "pub2.txt"),
              "shared-pub-payload");
}

TEST(RemoteContentRecoveryContract,
     SharedContentAcrossMultiplePathsDeduplicatesRepair) {
    auto f = make_recovery_fixture("recovery-shared-dedup");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "copy1.txt", "identical-content");
    kasumi::test::write_text(f.local_a / "copy2.txt", "identical-content");
    const auto initial_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(initial_sync.has_value());

    const auto cid = content_id_for(f.master_hex, "identical-content");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid));

    // Repair sync: both paths remain logically represented in the plan, while
    // physical transfer is deduplicated to a single content upload.
    kasumi::platform::perf_trace::force_enable(true);
    const auto repair_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    const auto elided =
        kasumi::platform::perf_trace::get_count("content uploads elided");
    kasumi::platform::perf_trace::force_enable(false);
    ASSERT_TRUE(repair_sync.has_value());
    const auto* comp =
        std::get_if<kasumi::application::SyncCompleted>(&repair_sync->data);
    ASSERT_NE(comp, nullptr);
    EXPECT_EQ(comp->uploaded, 2U);
    EXPECT_EQ(elided, 1U);
    EXPECT_FALSE(comp->published);
    EXPECT_EQ(kasumi::transport::presence(storage, cid).value(),
              kasumi::transport::Presence::Present);
}

TEST(RemoteContentRecoveryContract,
     SharedUpdateFromMissingRemoteContentUpdatesAllLogicalPathsAndConverges) {
    auto f = make_recovery_fixture("recovery-shared-update-from-missing");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    // 1. Both a.txt and b.txt start at H0; keep_repair.txt and pending_file.txt
    // are also initialized.
    kasumi::test::write_text(f.local_a / "a.txt", "v0-shared-payload");
    kasumi::test::write_text(f.local_a / "b.txt", "v0-shared-payload");
    kasumi::test::write_text(f.local_a / "keep_repair.txt", "v1-shared-payload");
    kasumi::test::write_text(f.local_a / "pending_file.txt", "pending-v0");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));

    // Device B updates pending_file.txt to pending-v1, then we remove
    // pending-v1's remote object so Device A observes pending_file.txt as
    // missing without local source.
    kasumi::test::write_text(f.local_b / "pending_file.txt", "pending-v1");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));
    std::filesystem::remove(f.local_a / "pending_file.txt");

    // 2. Physically remove H0 ("v0-shared-payload"), H1 ("v1-shared-payload"),
    // and "pending-v1" from remote storage.
    const auto cid_h0 = content_id_for(f.master_hex, "v0-shared-payload");
    const auto cid_h1 = content_id_for(f.master_hex, "v1-shared-payload");
    const auto cid_pend = content_id_for(f.master_hex, "pending-v1");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_h0));
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_h1));
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_pend));

    // 3. On Device A:
    // - Both a.txt and b.txt (whose remote H0 is missing) are modified to H1
    //   with distinct mtimes.
    // - keep_repair.txt still has H1 (physical repair coexisting with logical
    //   upload of H1).
    // - Two new files new1.txt and new2.txt are created with identical content.
    // - pending_file.txt is missing remotely without local source.
    kasumi::test::write_text(f.local_a / "a.txt", "v1-shared-payload");
    kasumi::test::write_text(f.local_a / "b.txt", "v1-shared-payload");
    const auto now = std::filesystem::file_time_type::clock::now();
    const auto mtime_a = now - std::chrono::seconds{120};
    const auto mtime_b = now - std::chrono::seconds{60};
    ASSERT_TRUE(
        kasumi::platform::metadata::set_last_write_time(f.local_a / "a.txt", mtime_a));
    ASSERT_TRUE(
        kasumi::platform::metadata::set_last_write_time(f.local_a / "b.txt", mtime_b));

    kasumi::test::write_text(f.local_a / "new1.txt", "new-identical-payload");
    kasumi::test::write_text(f.local_a / "new2.txt", "new-identical-payload");

    kasumi::platform::perf_trace::force_enable(true);
    const auto sync_a =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    const auto elided =
        kasumi::platform::perf_trace::get_count("content uploads elided");
    kasumi::platform::perf_trace::force_enable(false);
    ASSERT_TRUE(sync_a.has_value()) << sync_a.error().detail;
    const auto* comp_a =
        std::get_if<kasumi::application::SyncCompleted>(&sync_a->data);
    ASSERT_NE(comp_a, nullptr);
    EXPECT_TRUE(comp_a->published);
    // 5 logical upload operations (a.txt, b.txt, keep_repair.txt for H1;
    // new1.txt, new2.txt for H_new) -> 2 physical uploads, 3 elided!
    EXPECT_EQ(comp_a->uploaded, 5U);
    EXPECT_EQ(elided, 3U);
    // Only pending_file.txt should be pending; neither a.txt nor b.txt may stay
    // stuck at H0 or pending.
    ASSERT_EQ(comp_a->pending_paths.size(), 1U);
    EXPECT_EQ(comp_a->pending_paths.front(), "pending_file.txt");

    const auto paths_a =
        kasumi::runtime::resolve_profile_paths(f.env_a.app_data_dir, "demo");
    ASSERT_TRUE(paths_a.has_value());
    const auto state_a =
        kasumi::state_storage::load_state(paths_a->database_path);
    ASSERT_TRUE(state_a.has_value() && *state_a);
    const auto expected_h1 = kasumi::hasher::hash_string("v1-shared-payload");
    const auto* row_a = kasumi::find_row((*state_a)->tree, "a.txt");
    const auto* row_b = kasumi::find_row((*state_a)->tree, "b.txt");
    ASSERT_NE(row_a, nullptr);
    ASSERT_NE(row_b, nullptr);
    EXPECT_EQ(row_a->hash, expected_h1);
    EXPECT_EQ(row_b->hash, expected_h1);
    EXPECT_NE(row_a->mtime, row_b->mtime);
    EXPECT_NE(kasumi::find_row((*state_a)->tree, "new1.txt"), nullptr);
    EXPECT_NE(kasumi::find_row((*state_a)->tree, "new2.txt"), nullptr);

    // 4. Device B syncs (also repairing pending-v1 from its local copy) and
    // converges on all paths!
    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value()) << sync_b.error().detail;
    const auto* comp_b =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(comp_b, nullptr);
    EXPECT_FALSE(comp_b->partial);
    EXPECT_EQ(kasumi::test::read_text(f.local_b / "a.txt"), "v1-shared-payload");
    EXPECT_EQ(kasumi::test::read_text(f.local_b / "b.txt"), "v1-shared-payload");
    EXPECT_EQ(kasumi::test::read_text(f.local_b / "new1.txt"),
              "new-identical-payload");
    EXPECT_EQ(kasumi::test::read_text(f.local_b / "new2.txt"),
              "new-identical-payload");
}

TEST(RemoteContentRecoveryContract,
     ConflictingFilesWithSharedHashPreserveDistinctMtimesAndBothPaths) {
    auto f = make_recovery_fixture("recovery-conflict-shared-hash-mtime");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    kasumi::test::write_text(f.local_a / "conf1.txt", "base-1");
    kasumi::test::write_text(f.local_a / "conf2.txt", "base-2");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));

    const auto now = std::filesystem::file_time_type::clock::now();
    const auto t_local_1 = now + std::chrono::seconds{30};
    const auto t_local_2 = now + std::chrono::seconds{60};
    const auto t_remote = now + std::chrono::seconds{180};

    // Device A publishes newer remote versions for both files.
    kasumi::test::write_text(f.local_a / "conf1.txt", "remote-winner-1");
    kasumi::test::write_text(f.local_a / "conf2.txt", "remote-winner-2");
    ASSERT_TRUE(kasumi::platform::metadata::set_last_write_time(
        f.local_a / "conf1.txt", t_remote));
    ASSERT_TRUE(kasumi::platform::metadata::set_last_write_time(
        f.local_a / "conf2.txt", t_remote));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

    // Device B modifies both files to identical content with distinct mtimes
    // older than remote (so both become .kasumiconflict_local via RenameLocal).
    kasumi::test::write_text(f.local_b / "conf1.txt", "shared-conflict-body");
    kasumi::test::write_text(f.local_b / "conf2.txt", "shared-conflict-body");
    ASSERT_TRUE(kasumi::platform::metadata::set_last_write_time(
        f.local_b / "conf1.txt", t_local_1));
    ASSERT_TRUE(kasumi::platform::metadata::set_last_write_time(
        f.local_b / "conf2.txt", t_local_2));
    const auto expected_mtime_1 = *kasumi::platform::metadata::unix_nanoseconds(
        *kasumi::platform::metadata::last_write_time(f.local_b / "conf1.txt"));
    const auto expected_mtime_2 = *kasumi::platform::metadata::unix_nanoseconds(
        *kasumi::platform::metadata::last_write_time(f.local_b / "conf2.txt"));
    ASSERT_NE(expected_mtime_1, expected_mtime_2);

    kasumi::platform::perf_trace::force_enable(true);
    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    const auto elided =
        kasumi::platform::perf_trace::get_count("content uploads elided");
    kasumi::platform::perf_trace::force_enable(false);
    ASSERT_TRUE(sync_b.has_value()) << sync_b.error().detail;
    EXPECT_EQ(elided, 1U);

    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    const auto state_b =
        kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(state_b.has_value() && *state_b);
    const auto* row_c1 = kasumi::find_row(
        (*state_b)->tree, "conf1.txt.kasumiconflict_local");
    const auto* row_c2 = kasumi::find_row(
        (*state_b)->tree, "conf2.txt.kasumiconflict_local");
    ASSERT_NE(row_c1, nullptr);
    ASSERT_NE(row_c2, nullptr);
    EXPECT_EQ(row_c1->mtime, expected_mtime_1);
    EXPECT_EQ(row_c2->mtime, expected_mtime_2);
}

TEST(RemoteContentRecoveryContract,
     FileOnlyInRemoteTreeMissingContentRecordedPending) {
    auto f = make_recovery_fixture("recovery-remote-only-missing");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "remote_only.txt", "remote-only-bytes");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto cid = content_id_for(f.master_hex, "remote-only-bytes");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid));

    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value());
    const auto* comp =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(comp, nullptr);
    EXPECT_TRUE(comp->partial);
    EXPECT_FALSE(std::filesystem::exists(f.local_b / "remote_only.txt"));
}

TEST(RemoteContentRecoveryContract,
     ConcurrentRepairByTwoDevicesConvergesWithoutExtraCommit) {
    auto f = make_recovery_fixture("recovery-concurrent-repair-ab");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "shared.txt",
                             "concurrent-repair-payload");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));

    const auto cid = content_id_for(f.master_hex, "concurrent-repair-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid));

    // Device A observes cid absent and plans repair; right before A executes
    // its PUT for cid, Device B runs a complete repair Sync first.
    static decltype(storage.storage.put) s_real_put = nullptr;
    static ExecutionEnvironment s_env_b;
    static std::string s_cid;
    static bool s_b_ran = false;
    s_env_b = f.env_b;
    s_cid = cid;
    s_b_ran = false;

    const auto sync_a = execute_sync_with_hook(
        request(Operation::Sync, f.env_a),
        [](kasumi::transport::Transport& hooked) {
            s_real_put = hooked.storage.put;
            hooked.storage.put_batch = nullptr;
            hooked.storage.put = [](void* state,
                                    const std::filesystem::path& src,
                                    std::string_view id) -> kasumi::transport::Result {
                if (!s_b_ran && id == s_cid) {
                    s_b_ran = true;
                    const auto sync_b = kasumi::application::execute(
                        request(Operation::Sync, s_env_b));
                    EXPECT_TRUE(sync_b.has_value());
                    if (sync_b) {
                        const auto* comp_b =
                            std::get_if<kasumi::application::SyncCompleted>(
                                &sync_b->data);
                        EXPECT_NE(comp_b, nullptr);
                        if (comp_b) {
                            EXPECT_EQ(comp_b->uploaded, 1U);
                            EXPECT_FALSE(comp_b->published);
                        }
                    }
                }
                return s_real_put(state, src, id);
            };
        });
    ASSERT_TRUE(sync_a.has_value()) << sync_a.error().detail;
    EXPECT_TRUE(s_b_ran);
    const auto* comp_a =
        std::get_if<kasumi::application::SyncCompleted>(&sync_a->data);
    ASSERT_NE(comp_a, nullptr);
    EXPECT_EQ(comp_a->uploaded, 1U);
    EXPECT_FALSE(comp_a->published);
    EXPECT_EQ(kasumi::transport::presence(storage, cid).value(),
              kasumi::transport::Presence::Present);

    // Subsequent Sync on both devices is a clean no-op.
    const auto noop_a =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(noop_a.has_value());
    EXPECT_FALSE(
        std::get<kasumi::application::SyncCompleted>(noop_a->data).published);
}

TEST(RemoteContentRecoveryContract,
     ConcurrentRepairAndNewCommitOnOtherPathReobservesAndConverges) {
    auto f = make_recovery_fixture("recovery-concurrent-repair-new-commit");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "repair_me.txt", "repair-me-payload");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));

    const auto cid_repair = content_id_for(f.master_hex, "repair-me-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_repair));

    // During Device A's initial availability check, Device B publishes a new
    // commit adding other.txt, while cid_repair remains absent until A repairs it.
    static decltype(storage.storage.presence) s_real_presence = nullptr;
    static ExecutionEnvironment s_env_b;
    static std::filesystem::path s_local_b;
    static kasumi::transport::Transport* s_storage = nullptr;
    static std::string s_cid_repair;
    static bool s_injected = false;
    s_env_b = f.env_b;
    s_local_b = f.local_b;
    s_storage = &storage;
    s_cid_repair = cid_repair;
    s_injected = false;

    const auto sync_a = execute_sync_with_hook(
        request(Operation::Sync, f.env_a),
        [](kasumi::transport::Transport& hooked) {
            s_real_presence = hooked.storage.presence;
            hooked.storage.control_read_batch = nullptr;
            hooked.storage.presence =
                [](void* state,
                   std::string_view id) -> kasumi::transport::PresenceResult {
                auto res = s_real_presence(state, id);
                if (!s_injected && id == s_cid_repair) {
                    s_injected = true;
                    kasumi::test::write_text(s_local_b / "other.txt",
                                             "other-new-commit");
                    const auto sync_b = kasumi::application::execute(
                        request(Operation::Sync, s_env_b));
                    EXPECT_TRUE(sync_b.has_value());
                    // Keep cid_repair absent so Device A must still repair it
                    // after reobserving B's new head during stabilize.
                    (void)kasumi::transport::remove(*s_storage, s_cid_repair);
                }
                return res;
            };
        });
    ASSERT_TRUE(sync_a.has_value()) << sync_a.error().detail;
    EXPECT_TRUE(s_injected);
    const auto* comp_a =
        std::get_if<kasumi::application::SyncCompleted>(&sync_a->data);
    ASSERT_NE(comp_a, nullptr);
    EXPECT_EQ(comp_a->uploaded, 1U);
    EXPECT_EQ(comp_a->downloaded, 1U);
    EXPECT_EQ(kasumi::transport::presence(storage, cid_repair).value(),
              kasumi::transport::Presence::Present);
    EXPECT_EQ(kasumi::test::read_text(f.local_a / "other.txt"),
              "other-new-commit");
    EXPECT_EQ(kasumi::test::read_text(f.local_a / "repair_me.txt"),
              "repair-me-payload");
}

TEST(RemoteContentRecoveryContract,
     ConcurrentDownloadVsRepairRaceMaterializesWithoutLogicalDeletion) {
    auto f = make_recovery_fixture("recovery-concurrent-download-vs-repair");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "race.txt", "race-payload");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

    const auto cid_race = content_id_for(f.master_hex, "race-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_race));

    // Device B (no local copy) sees cid_race missing from LIST, but before B's
    // targeted presence probe executes, Device A repairs cid_race.
    static decltype(storage.storage.presence) s_real_presence = nullptr;
    static ExecutionEnvironment s_env_a;
    static std::string s_cid_race;
    static bool s_repaired = false;
    s_env_a = f.env_a;
    s_cid_race = cid_race;
    s_repaired = false;

    const auto sync_b = execute_sync_with_hook(
        request(Operation::Sync, f.env_b),
        [](kasumi::transport::Transport& hooked) {
            s_real_presence = hooked.storage.presence;
            hooked.storage.control_read_batch = nullptr;
            hooked.storage.presence =
                [](void* state,
                   std::string_view id) -> kasumi::transport::PresenceResult {
                if (!s_repaired && id == s_cid_race) {
                    s_repaired = true;
                    const auto repair_a = kasumi::application::execute(
                        request(Operation::Sync, s_env_a));
                    EXPECT_TRUE(repair_a.has_value());
                }
                return s_real_presence(state, id);
            };
        });
    ASSERT_TRUE(sync_b.has_value()) << sync_b.error().detail;
    EXPECT_TRUE(s_repaired);
    const auto* comp_b =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(comp_b, nullptr);
    EXPECT_FALSE(comp_b->partial);
    EXPECT_FALSE(comp_b->published);
    EXPECT_EQ(comp_b->downloaded, 1U);
    EXPECT_EQ(kasumi::test::read_text(f.local_b / "race.txt"), "race-payload");
}

TEST(RemoteContentRecoveryContract,
     LogicalConflictDuringPhysicalAbsenceAndConcurrentRepairPreservesBothVersions) {
    auto f = make_recovery_fixture("recovery-conflict-during-absence");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "conflict_doc.txt", "base-v0");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));

    // Device A publishes version-from-a; Device B edits locally to version-from-b.
    kasumi::test::write_text(f.local_a / "conflict_doc.txt", "version-from-a");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    kasumi::test::write_text(f.local_b / "conflict_doc.txt", "version-from-b");

    // Physically remove both base-v0 (permanently absent) and version-from-a
    // (concurrently repaired by Device A while Device B audits availability).
    const auto cid_base = content_id_for(f.master_hex, "base-v0");
    const auto cid_a = content_id_for(f.master_hex, "version-from-a");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_base));
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_a));

    static decltype(storage.storage.presence) s_real_presence = nullptr;
    static ExecutionEnvironment s_env_a;
    static std::string s_cid_a;
    static bool s_repaired_a = false;
    s_env_a = f.env_a;
    s_cid_a = cid_a;
    s_repaired_a = false;

    const auto sync_b = execute_sync_with_hook(
        request(Operation::Sync, f.env_b),
        [](kasumi::transport::Transport& hooked) {
            s_real_presence = hooked.storage.presence;
            hooked.storage.control_read_batch = nullptr;
            hooked.storage.presence =
                [](void* state,
                   std::string_view id) -> kasumi::transport::PresenceResult {
                if (!s_repaired_a && id == s_cid_a) {
                    s_repaired_a = true;
                    const auto repair_a = kasumi::application::execute(
                        request(Operation::Sync, s_env_a));
                    EXPECT_TRUE(repair_a.has_value());
                }
                return s_real_presence(state, id);
            };
        });
    ASSERT_TRUE(sync_b.has_value()) << sync_b.error().detail;
    EXPECT_TRUE(s_repaired_a);
    EXPECT_EQ(kasumi::transport::presence(storage, cid_base).value(),
              kasumi::transport::Presence::Absent);
    EXPECT_EQ(kasumi::transport::presence(storage, cid_a).value(),
              kasumi::transport::Presence::Present);

    const auto sync_a_converge =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(sync_a_converge.has_value()) << sync_a_converge.error().detail;

    auto collect_contents = [](const std::filesystem::path& dir) {
        std::vector<std::string> out;
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            if (entry.is_regular_file()) {
                out.push_back(kasumi::test::read_text(entry.path()));
            }
        }
        std::ranges::sort(out);
        return out;
    };
    const auto contents_b = collect_contents(f.local_b);
    const auto contents_a = collect_contents(f.local_a);
    ASSERT_EQ(contents_b.size(), 2U);
    EXPECT_EQ(contents_b[0], "version-from-a");
    EXPECT_EQ(contents_b[1], "version-from-b");
    EXPECT_EQ(contents_a, contents_b);
}

TEST(RemoteContentRecoveryContract,
     ConcurrentLogicalDeletionWinsOverPhysicalRepairWithoutResurrection) {
    auto f = make_recovery_fixture("recovery-concurrent-delete-vs-repair");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::test::write_text(f.local_a / "vanish.txt", "vanish-payload");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));

    const auto cid_vanish = content_id_for(f.master_hex, "vanish-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_vanish));

    // Device A starts Sync and observes cid_vanish absent; before A enters
    // stabilize, Device B deletes vanish.txt and publishes the deletion commit.
    static decltype(storage.storage.presence) s_real_presence = nullptr;
    static ExecutionEnvironment s_env_b;
    static std::filesystem::path s_local_b;
    static std::string s_cid_vanish;
    static bool s_deleted_on_b = false;
    s_env_b = f.env_b;
    s_local_b = f.local_b;
    s_cid_vanish = cid_vanish;
    s_deleted_on_b = false;

    const auto sync_a = execute_sync_with_hook(
        request(Operation::Sync, f.env_a),
        [](kasumi::transport::Transport& hooked) {
            s_real_presence = hooked.storage.presence;
            hooked.storage.control_read_batch = nullptr;
            hooked.storage.presence =
                [](void* state,
                   std::string_view id) -> kasumi::transport::PresenceResult {
                auto res = s_real_presence(state, id);
                if (!s_deleted_on_b && id == s_cid_vanish) {
                    s_deleted_on_b = true;
                    std::filesystem::remove(s_local_b / "vanish.txt");
                    const auto sync_b = kasumi::application::execute(
                        request(Operation::Sync, s_env_b));
                    EXPECT_TRUE(sync_b.has_value());
                }
                return res;
            };
        });
    ASSERT_TRUE(sync_a.has_value()) << sync_a.error().detail;
    EXPECT_TRUE(s_deleted_on_b);
    const auto* comp_a =
        std::get_if<kasumi::application::SyncCompleted>(&sync_a->data);
    ASSERT_NE(comp_a, nullptr);
    EXPECT_EQ(comp_a->uploaded, 0U);
    EXPECT_EQ(comp_a->removed, 1U);
    EXPECT_FALSE(comp_a->published);
    EXPECT_FALSE(std::filesystem::exists(f.local_a / "vanish.txt"));
    EXPECT_EQ(kasumi::transport::presence(storage, cid_vanish).value(),
              kasumi::transport::Presence::Absent);
}

TEST(RemoteContentRecoveryContract,
     LogicalConflictsRemainIntactDuringAvailabilityCheck) {
    auto f = make_recovery_fixture("recovery-conflicts-intact");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    kasumi::test::write_text(f.local_a / "base.txt", "base");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));

    // Divergent edits on both devices.
    kasumi::test::write_text(f.local_a / "base.txt", "edit-from-a");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

    kasumi::test::write_text(f.local_b / "base.txt", "edit-from-b");
    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value()) << sync_b.error().detail;
    const auto* comp_b =
        std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(comp_b, nullptr);
    EXPECT_TRUE(comp_b->published);
    EXPECT_FALSE(comp_b->partial);

    // Verify both base.txt and its .kasumiconflict_ sibling exist on B with
    // the two divergent payloads preserved.
    std::string conflict_rel_path;
    std::vector<std::string> contents_b;
    for (const auto& entry : std::filesystem::directory_iterator(f.local_b)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto name = entry.path().filename().string();
        if (name.starts_with("base.txt.kasumiconflict_")) {
            conflict_rel_path = name;
        }
        contents_b.push_back(kasumi::test::read_text(entry.path()));
    }
    ASSERT_FALSE(conflict_rel_path.empty());
    std::ranges::sort(contents_b);
    ASSERT_EQ(contents_b.size(), 2U);
    EXPECT_EQ(contents_b[0], "edit-from-a");
    EXPECT_EQ(contents_b[1], "edit-from-b");

    const auto paths_b =
        kasumi::runtime::resolve_profile_paths(f.env_b.app_data_dir, "demo");
    ASSERT_TRUE(paths_b.has_value());
    const auto state_b =
        kasumi::state_storage::load_state(paths_b->database_path);
    ASSERT_TRUE(state_b.has_value() && *state_b);
    EXPECT_NE(kasumi::find_row((*state_b)->tree, "base.txt"), nullptr);
    EXPECT_NE(kasumi::find_row((*state_b)->tree, conflict_rel_path), nullptr);

    // Device A syncs again and converges on both files.
    const auto sync_a2 =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(sync_a2.has_value()) << sync_a2.error().detail;
    EXPECT_TRUE(std::filesystem::exists(f.local_a / "base.txt"));
    EXPECT_TRUE(std::filesystem::exists(f.local_a / conflict_rel_path));
    EXPECT_EQ(kasumi::test::read_text(f.local_a / "base.txt"),
              kasumi::test::read_text(f.local_b / "base.txt"));
    EXPECT_EQ(kasumi::test::read_text(f.local_a / conflict_rel_path),
              kasumi::test::read_text(f.local_b / conflict_rel_path));
}

TEST(RemoteContentRecoveryContract, OptimizedHistoryLoadingPreserved) {
    auto f = make_recovery_fixture("recovery-optimized-history");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));

    kasumi::test::write_text(f.local_a / "hist.txt", "commit-1");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    kasumi::test::write_text(f.local_a / "hist.txt", "commit-2");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    kasumi::test::write_text(f.local_a / "hist.txt", "commit-3");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    const auto key = kasumi::runtime::vault::decode_hex(f.master_hex);
    ASSERT_TRUE(key.has_value());

    const auto paths_a =
        kasumi::runtime::resolve_profile_paths(f.env_a.app_data_dir, "demo");
    ASSERT_TRUE(paths_a.has_value());
    const kasumi::runtime::RuntimeData runtime_data{
        .local_dir = f.local_a,
        .database_path = paths_a->database_path,
        .key_path = paths_a->key_path,
        .storage_location = f.remote_dir.string()};

    // Scoped observation must have audit_storage_objects = false.
    kasumi::application::observation::LocalObservationSession session;
    auto input = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *opened, *key, false, {}, &session);
    ASSERT_TRUE(input.has_value());
    EXPECT_FALSE(input->audit_storage_objects);

    // Full Sync with matching base_commit_id must run content availability
    // listing without downloading/decrypting any historical commit objects.
    kasumi::platform::perf_trace::force_enable(true);
    const auto noop_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    const auto content_list_count =
        kasumi::platform::perf_trace::get_count("sync content listing");
    const auto get_commit_count =
        kasumi::platform::perf_trace::get_count("rc/get_commit");
    const auto get_content_count =
        kasumi::platform::perf_trace::get_count("rc/get_content");
    kasumi::platform::perf_trace::force_enable(false);

    ASSERT_TRUE(noop_sync.has_value()) << noop_sync.error().detail;
    EXPECT_GE(content_list_count, 1U);
    EXPECT_EQ(get_commit_count, 0U);
    EXPECT_EQ(get_content_count, 0U);
}

TEST(RemoteContentRecoveryContract, GcRegressionsPassIntact) {
    auto f = make_recovery_fixture("recovery-gc-regressions-intact");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));

    kasumi::test::write_text(f.local_a / "live.txt", "live-gc-payload");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    const auto key = kasumi::runtime::vault::decode_hex(f.master_hex);
    ASSERT_TRUE(key.has_value());

    // 1. Add an orphan content object and a redundant commit variant.
    const auto orphan_id = kasumi::crypto::content_identifier(
        *key, kasumi::hasher::hash_string("orphan-gc-payload"));
    const auto plain =
        kasumi::test::workspace_path(f.workspace, "orphan_gc.plain");
    const auto enc = kasumi::test::workspace_path(f.workspace, "orphan_gc.enc");
    kasumi::test::write_text(plain, "orphan-gc-payload");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, enc, *key));
    ASSERT_TRUE(kasumi::transport::put(storage, enc, orphan_id));

    const auto loaded = kasumi::application::history_storage::load_history(
        storage, *key, f.env_a.app_data_dir);
    ASSERT_TRUE(loaded.has_value()) << loaded.error().detail;
    ASSERT_FALSE(loaded->commits.empty());
    const auto canonical =
        kasumi::history::serialize(loaded->commits.back().commit).value();
    const auto var_plain =
        kasumi::test::workspace_path(f.workspace, "var_gc.plain");
    const auto var_enc =
        kasumi::test::workspace_path(f.workspace, "var_gc.enc");
    kasumi::test::write_binary(var_plain, std::as_bytes(std::span{canonical}));
    ASSERT_TRUE(kasumi::crypto::encrypt_file(
        var_plain, var_enc, *key, kasumi::crypto::FilePurpose::History));
    const auto var_hash = kasumi::crypto::content::hash_file(var_enc).value();
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(*key);
    const kasumi::application::history_storage::HeadReference extra_variant{
        .commit_id = kasumi::crypto::commit_identifier(*key, canonical),
        .ciphertext_id = kasumi::hash_hex(var_hash),
    };
    ASSERT_TRUE(kasumi::transport::put(
        storage,
        var_enc,
        kasumi::application::history_storage::commit_object(layout,
                                                            extra_variant)));

    // 2. GarbageCollect classifies and quarantines both candidates while
    // preserving live.txt's content object.
    const auto gc =
        kasumi::application::execute(request(Operation::GarbageCollect, f.env_a));
    ASSERT_TRUE(gc.has_value()) << gc.error().detail;
    const auto* gc_comp =
        std::get_if<kasumi::application::GarbageCollectCompleted>(&gc->data);
    ASSERT_NE(gc_comp, nullptr);
    EXPECT_EQ(gc_comp->content_candidate_objects, 1U);
    EXPECT_EQ(gc_comp->commit_variant_candidate_objects, 1U);
    EXPECT_EQ(gc_comp->candidate_objects, 2U);
    EXPECT_EQ(gc_comp->directly_removed_objects, 1U);
    EXPECT_EQ(gc_comp->quarantined_objects, 1U);

    const auto live_cid = content_id_for(f.master_hex, "live-gc-payload");
    EXPECT_EQ(kasumi::transport::presence(storage, live_cid).value(),
              kasumi::transport::Presence::Present);

    // 3. If live_cid is subsequently lost on remote storage, Sync repairs it
    // and Fsck succeeds afterward.
    ASSERT_TRUE(kasumi::transport::remove(storage, live_cid));
    const auto repair_sync =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(repair_sync.has_value()) << repair_sync.error().detail;
    EXPECT_EQ(kasumi::transport::presence(storage, live_cid).value(),
              kasumi::transport::Presence::Present);
    const auto fsck =
        kasumi::application::execute(request(Operation::Fsck, f.env_a));
    ASSERT_TRUE(fsck.has_value()) << fsck.error().detail;
}

TEST(RemoteContentRecoveryContract,
     StaleKnownMissingClearedAfterLogicalDeletionAndDoesNotTriggerRepair) {
    auto f = make_recovery_fixture("recovery-stale-missing-after-deletion");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    const auto key = kasumi::runtime::vault::decode_hex(f.master_hex);
    ASSERT_TRUE(key.has_value());

    // 1. Remote history initially references X ("x-obsolete-payload") on both
    // devices.
    kasumi::test::write_text(f.local_a / "x.txt", "x-obsolete-payload");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));

    // 2. X is physically absent from remote storage.
    const auto hash_x = kasumi::hasher::hash_string("x-obsolete-payload");
    const auto cid_x = content_id_for(f.master_hex, "x-obsolete-payload");
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_x));

    // 3-4. PC A observes X absent; known_missing_content_objects contains hash_x
    // and the initial plan schedules a repair Upload of x.txt.
    const auto paths_a =
        kasumi::runtime::resolve_profile_paths(f.env_a.app_data_dir, "demo");
    ASSERT_TRUE(paths_a.has_value());
    const kasumi::runtime::RuntimeData runtime_a{
        .local_dir = f.local_a,
        .database_path = paths_a->database_path,
        .key_path = paths_a->key_path,
        .storage_location = f.remote_dir.string()};
    auto input_a = kasumi::application::observation::collect_reconciliation_input(
        runtime_a, storage, *key, false);
    ASSERT_TRUE(input_a.has_value()) << input_a.error().detail;
    auto initial_plan = kasumi::reconciliation::reconcile(*input_a);
    ASSERT_TRUE(initial_plan.has_value()) << initial_plan.error().detail;
    ASSERT_TRUE(kasumi::application::sync::coordinator::reobservation::
                    observe_content_availability(
                        *input_a, *initial_plan, storage, *key));
    EXPECT_TRUE(input_a->known_missing_content_objects.contains(hash_x));
    auto repair_plan = kasumi::reconciliation::reconcile(*input_a);
    ASSERT_TRUE(repair_plan.has_value()) << repair_plan.error().detail;
    EXPECT_TRUE(repair_plan->requires_storage_repair);
    EXPECT_FALSE(repair_plan->requires_publication);

    // 5. PC B publishes a legitimate logical deletion of x.txt.
    std::filesystem::remove(f.local_b / "x.txt");
    const auto sync_b =
        kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value()) << sync_b.error().detail;

    // 6-8. PC A reobserves remote history while input_a still carries the prior
    // known_missing_content_objects (and confirmed_missing = {hash_x}).
    auto reobserved =
        kasumi::application::observation::collect_reconciliation_input(
            runtime_a, storage, *key, false);
    ASSERT_TRUE(reobserved.has_value()) << reobserved.error().detail;
    input_a->storage = std::move(reobserved->storage);
    ASSERT_TRUE(input_a->known_missing_content_objects.contains(hash_x));

    auto pre_availability = kasumi::reconciliation::reconcile(*input_a);
    ASSERT_TRUE(pre_availability.has_value()) << pre_availability.error().detail;
    EXPECT_FALSE(pre_availability->requires_storage_repair);
    EXPECT_FALSE(pre_availability->requires_publication);
    EXPECT_TRUE(pre_availability->missing_objects.empty());
    EXPECT_EQ(kasumi::find_row(pre_availability->candidate_shared_tree, "x.txt"),
              nullptr);
    EXPECT_TRUE(std::ranges::none_of(
        pre_availability->plan.operations, [](const kasumi::Operation& op) {
            return op.action == kasumi::Action::Upload;
        }));

    const std::array<kasumi::Hash, 1> confirmed_x{hash_x};
    ASSERT_TRUE(kasumi::application::sync::coordinator::reobservation::
                    observe_content_availability(*input_a,
                                                 *pre_availability,
                                                 storage,
                                                 *key,
                                                 confirmed_x));
    EXPECT_TRUE(input_a->known_missing_content_objects.empty());

    auto final_plan = kasumi::reconciliation::reconcile(*input_a);
    ASSERT_TRUE(final_plan.has_value()) << final_plan.error().detail;
    EXPECT_FALSE(final_plan->requires_storage_repair);
    EXPECT_FALSE(final_plan->requires_publication);
    EXPECT_TRUE(final_plan->missing_objects.empty());
    EXPECT_EQ(kasumi::find_row(final_plan->candidate_shared_tree, "x.txt"),
              nullptr);
    ASSERT_EQ(final_plan->plan.operations.size(), 1U);
    EXPECT_EQ(final_plan->plan.operations.front().action,
              kasumi::Action::DeleteLocal);
    EXPECT_EQ(final_plan->plan.operations.front().path, "x.txt");

    // Execute full Sync on PC A and verify convergence on subsequent Sync.
    const auto sync_a =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(sync_a.has_value()) << sync_a.error().detail;
    const auto* comp_a =
        std::get_if<kasumi::application::SyncCompleted>(&sync_a->data);
    ASSERT_NE(comp_a, nullptr);
    EXPECT_EQ(comp_a->uploaded, 0U);
    EXPECT_EQ(comp_a->removed, 1U);
    EXPECT_FALSE(comp_a->published);
    EXPECT_FALSE(std::filesystem::exists(f.local_a / "x.txt"));
    EXPECT_EQ(kasumi::transport::presence(storage, cid_x).value(),
              kasumi::transport::Presence::Absent);

    const auto sync_a_noop =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(sync_a_noop.has_value()) << sync_a_noop.error().detail;
    const auto* noop_a =
        std::get_if<kasumi::application::SyncCompleted>(&sync_a_noop->data);
    ASSERT_NE(noop_a, nullptr);
    EXPECT_EQ(noop_a->total, 0U);
    EXPECT_FALSE(noop_a->published);
}

TEST(RemoteContentRecoveryContract,
     ComplementaryCasesForMissingContentAcrossLogicalDeletionAndRestoration) {
    auto f = make_recovery_fixture("recovery-complementary-missing-cases");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    const auto key = kasumi::runtime::vault::decode_hex(f.master_hex);
    ASSERT_TRUE(key.has_value());
    const auto paths_a =
        kasumi::runtime::resolve_profile_paths(f.env_a.app_data_dir, "demo");
    ASSERT_TRUE(paths_a.has_value());
    const kasumi::runtime::RuntimeData runtime_a{
        .local_dir = f.local_a,
        .database_path = paths_a->database_path,
        .key_path = paths_a->key_path,
        .storage_location = f.remote_dir.string()};

    // Case A & B setup:
    // - a.txt and b.txt share hash X_shared ("shared-x-payload") on both PCs.
    // - delete_me.txt has hash X_del ("del-only-payload") on both PCs.
    // - pending_keep.txt has hash X_pend ("pending-keep-payload"), created on
    //   PC B only and physically removed before PC A syncs so PC A holds a
    //   legitimate pending materialization.
    kasumi::test::write_text(f.local_a / "a.txt", "shared-x-payload");
    kasumi::test::write_text(f.local_a / "b.txt", "shared-x-payload");
    kasumi::test::write_text(f.local_a / "delete_me.txt", "del-only-payload");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));

    kasumi::test::write_text(f.local_b / "pending_keep.txt",
                             "pending-keep-payload");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));

    const auto hash_shared = kasumi::hasher::hash_string("shared-x-payload");
    const auto hash_del = kasumi::hasher::hash_string("del-only-payload");
    const auto hash_pend = kasumi::hasher::hash_string("pending-keep-payload");
    const auto cid_shared = content_id_for(f.master_hex, "shared-x-payload");
    const auto cid_del = content_id_for(f.master_hex, "del-only-payload");
    const auto cid_pend = content_id_for(f.master_hex, "pending-keep-payload");

    ASSERT_TRUE(kasumi::transport::remove(storage, cid_shared));
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_del));
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_pend));

    // PC A observes all three hashes missing.
    auto input_a = kasumi::application::observation::collect_reconciliation_input(
        runtime_a, storage, *key, false);
    ASSERT_TRUE(input_a.has_value()) << input_a.error().detail;
    auto plan1 = kasumi::reconciliation::reconcile(*input_a);
    ASSERT_TRUE(plan1.has_value()) << plan1.error().detail;
    ASSERT_TRUE(kasumi::application::sync::coordinator::reobservation::
                    observe_content_availability(
                        *input_a, *plan1, storage, *key));
    EXPECT_TRUE(input_a->known_missing_content_objects.contains(hash_shared));
    EXPECT_TRUE(input_a->known_missing_content_objects.contains(hash_del));
    EXPECT_TRUE(input_a->known_missing_content_objects.contains(hash_pend));

    // PC B deletes a.txt (leaving b.txt referencing hash_shared) and deletes
    // delete_me.txt, while restoring cid_shared temporarily so B can publish,
    // then removing cid_shared again so A still needs to repair hash_shared.
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));
    std::filesystem::remove(f.local_b / "a.txt");
    std::filesystem::remove(f.local_b / "delete_me.txt");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_shared));
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_del));
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_pend));

    // PC A reobserves remote history while keeping its prior
    // known_missing_content_objects.
    auto reobs = kasumi::application::observation::collect_reconciliation_input(
        runtime_a, storage, *key, false);
    ASSERT_TRUE(reobs.has_value()) << reobs.error().detail;
    input_a->storage = std::move(reobs->storage);

    auto pre_replan = kasumi::reconciliation::reconcile(*input_a);
    ASSERT_TRUE(pre_replan.has_value()) << pre_replan.error().detail;
    ASSERT_TRUE(kasumi::application::sync::coordinator::reobservation::
                    observe_content_availability(
                        *input_a, *pre_replan, storage, *key));
    // Case A: hash_shared is still needed by b.txt!
    EXPECT_TRUE(input_a->known_missing_content_objects.contains(hash_shared));
    // Case B: hash_pend is still needed by pending_keep.txt!
    EXPECT_TRUE(input_a->known_missing_content_objects.contains(hash_pend));
    // Stale hash_del was logically deleted and must be cleared!
    EXPECT_FALSE(input_a->known_missing_content_objects.contains(hash_del));

    auto post_replan = kasumi::reconciliation::reconcile(*input_a);
    ASSERT_TRUE(post_replan.has_value()) << post_replan.error().detail;
    EXPECT_TRUE(post_replan->requires_storage_repair);
    EXPECT_EQ(kasumi::find_row(post_replan->candidate_shared_tree, "a.txt"),
              nullptr);
    EXPECT_EQ(kasumi::find_row(post_replan->candidate_shared_tree, "delete_me.txt"),
              nullptr);
    ASSERT_NE(kasumi::find_row(post_replan->candidate_shared_tree, "b.txt"),
              nullptr);
    ASSERT_EQ(post_replan->pending_materializations.size(), 1U);
    EXPECT_EQ(post_replan->pending_materializations.front().path,
              "pending_keep.txt");
    // Repair upload must use surviving b.txt, never deleted a.txt or delete_me.txt.
    EXPECT_TRUE(std::ranges::any_of(
        post_replan->plan.operations, [&](const kasumi::Operation& op) {
            return op.action == kasumi::Action::Upload && op.path == "b.txt" &&
                   op.hash == kasumi::hash_hex(hash_shared);
        }));
    EXPECT_TRUE(std::ranges::none_of(
        post_replan->plan.operations, [](const kasumi::Operation& op) {
            return op.action == kasumi::Action::Upload &&
                   (op.path == "a.txt" || op.path == "delete_me.txt");
        }));

    // Execute Sync on PC A: deletes a.txt & delete_me.txt, repairs b.txt
    // (hash_shared), and records pending_keep.txt in pending_materializations.
    const auto sync_a =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(sync_a.has_value()) << sync_a.error().detail;
    EXPECT_EQ(kasumi::transport::presence(storage, cid_shared).value(),
              kasumi::transport::Presence::Present);
    EXPECT_FALSE(std::filesystem::exists(f.local_a / "a.txt"));
    EXPECT_FALSE(std::filesystem::exists(f.local_a / "delete_me.txt"));
    EXPECT_TRUE(std::filesystem::exists(f.local_a / "b.txt"));

    // Case D: When another device restores cid_pend, reobservation clears
    // hash_pend from known_missing_content_objects.
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));
    EXPECT_EQ(kasumi::transport::presence(storage, cid_pend).value(),
              kasumi::transport::Presence::Present);

    auto input_d = kasumi::application::observation::collect_reconciliation_input(
        runtime_a, storage, *key, false);
    ASSERT_TRUE(input_d.has_value()) << input_d.error().detail;
    input_d->known_missing_content_objects.insert(hash_pend);
    auto plan_d1 = kasumi::reconciliation::reconcile(*input_d);
    ASSERT_TRUE(plan_d1.has_value()) << plan_d1.error().detail;
    ASSERT_TRUE(kasumi::application::sync::coordinator::reobservation::
                    observe_content_availability(
                        *input_d, *plan_d1, storage, *key));
    EXPECT_FALSE(input_d->known_missing_content_objects.contains(hash_pend));

    // Case C: Concurrent physical repair on A followed by logical deletion on B
    // respects the deletion on the next Sync.
    ASSERT_TRUE(kasumi::transport::remove(storage, cid_shared));
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_a)));
    EXPECT_EQ(kasumi::transport::presence(storage, cid_shared).value(),
              kasumi::transport::Presence::Present);
    EXPECT_TRUE(std::filesystem::exists(f.local_a / "pending_keep.txt"));

    std::filesystem::remove(f.local_b / "b.txt");
    ASSERT_TRUE(
        kasumi::application::execute(request(Operation::Sync, f.env_b)));
    const auto sync_a_after_del =
        kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(sync_a_after_del.has_value()) << sync_a_after_del.error().detail;
    const auto* comp_c =
        std::get_if<kasumi::application::SyncCompleted>(&sync_a_after_del->data);
    ASSERT_NE(comp_c, nullptr);
    EXPECT_EQ(comp_c->uploaded, 0U);
    EXPECT_EQ(comp_c->removed, 1U);
    EXPECT_FALSE(comp_c->published);
    EXPECT_FALSE(std::filesystem::exists(f.local_a / "b.txt"));
}

TEST(SyncMaintenanceHybridGcTest, GroupE_E1_SyncBlockedByActiveGcBarrierAndGcAbortsOnActiveWriter) {
    auto f = make_recovery_fixture("recovery-a3-e1-barrier-writer");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));

    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    const auto key = kasumi::runtime::vault::decode_hex(f.master_hex);
    ASSERT_TRUE(key.has_value());
    const auto layout = kasumi::application::history_storage::derive_remote_layout(*key);

    // 1. Establish GC barrier: Sync must be blocked
    auto barrier = protocol::establish_barrier(storage, layout, f.env_a.app_data_dir);
    ASSERT_TRUE(barrier.has_value()) << barrier.error().detail;

    kasumi::test::write_text(f.local_a / "test.txt", "data");
    const auto sync_blocked = kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_FALSE(sync_blocked.has_value());

    // Release barrier
    ASSERT_TRUE(protocol::release_registration(*barrier).has_value());

    // 2. Register active writer: GC must abort
    auto writer = protocol::register_writer(storage, layout, f.env_a.app_data_dir);
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;

    const auto gc_aborted = kasumi::application::execute(request(Operation::GarbageCollect, f.env_a));
    ASSERT_FALSE(gc_aborted.has_value());

    ASSERT_TRUE(protocol::release_registration(*writer).has_value());
}

TEST(SyncMaintenanceHybridGcTest, GroupE_E2_SyncAfterHybridGcConvergesWithoutFalseAbsences) {
    auto f = make_recovery_fixture("recovery-a3-e2-converge-no-false-absence");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    // Device A uploads data.txt, B syncs it
    kasumi::test::write_text(f.local_a / "data.txt", "live data");
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_b)));

    // Put an unreferenced orphan content into remote storage
    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto key = kasumi::runtime::vault::decode_hex(f.master_hex);
    ASSERT_TRUE(key.has_value());

    const auto orphan_cid = kasumi::crypto::content_identifier(
        *key, kasumi::hasher::hash_string("orphan-unreferenced-content"));
    const auto plain = kasumi::test::workspace_path(f.workspace, "orphan.plain");
    const auto enc = kasumi::test::workspace_path(f.workspace, "orphan.enc");
    kasumi::test::write_text(plain, "orphan-unreferenced-content");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, enc, *key));
    ASSERT_TRUE(kasumi::transport::put(storage, enc, orphan_cid));

    // GC collects the unreferenced content directly
    const auto gc = kasumi::application::execute(request(Operation::GarbageCollect, f.env_a));
    ASSERT_TRUE(gc.has_value()) << gc.error().detail;
    const auto* gc_comp = std::get_if<kasumi::application::GarbageCollectCompleted>(&gc->data);
    ASSERT_NE(gc_comp, nullptr);
    EXPECT_EQ(gc_comp->directly_removed_objects, 1U);
    EXPECT_EQ(gc_comp->quarantined_objects, 0U);
    EXPECT_EQ(kasumi::transport::presence(storage, orphan_cid).value(),
              kasumi::transport::Presence::Absent);

    // Sync on A again: no-op, no false absences, no repair upload for deleted content
    const auto sync_a = kasumi::application::execute(request(Operation::Sync, f.env_a));
    ASSERT_TRUE(sync_a.has_value()) << sync_a.error().detail;
    const auto* comp_a = std::get_if<kasumi::application::SyncCompleted>(&sync_a->data);
    ASSERT_NE(comp_a, nullptr);
    EXPECT_EQ(comp_a->uploaded, 0U);
    EXPECT_FALSE(comp_a->published);
}

TEST(SyncMaintenanceHybridGcTest, GroupE_E3_ReuploadByAnotherNodeAfterDirectRemovalSucceeds) {
    auto f = make_recovery_fixture("recovery-a3-e3-reupload-succeeds");
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_a, f.profile_a, MasterKeyHex{f.master_hex}));
    ASSERT_TRUE(kasumi::application::create_profile(
        f.env_b, f.profile_b, MasterKeyHex{f.master_hex}));

    // Initialize vault with initial file
    kasumi::test::write_text(f.local_a / "init.txt", "init content");
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_b)));

    // Put an unreferenced orphan content into remote storage
    auto opened = kasumi::transport::open_transport(f.remote_dir.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto key = kasumi::runtime::vault::decode_hex(f.master_hex);
    ASSERT_TRUE(key.has_value());

    const auto reupload_text = "content-to-be-removed-then-reuploaded";
    const auto orphan_cid = kasumi::crypto::content_identifier(
        *key, kasumi::hasher::hash_string(reupload_text));
    const auto plain = kasumi::test::workspace_path(f.workspace, "reupload.plain");
    const auto enc = kasumi::test::workspace_path(f.workspace, "reupload.enc");
    kasumi::test::write_text(plain, reupload_text);
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, enc, *key));
    ASSERT_TRUE(kasumi::transport::put(storage, enc, orphan_cid));

    // GC removes content directly
    const auto gc = kasumi::application::execute(request(Operation::GarbageCollect, f.env_a));
    ASSERT_TRUE(gc.has_value()) << gc.error().detail;
    const auto* gc_comp = std::get_if<kasumi::application::GarbageCollectCompleted>(&gc->data);
    ASSERT_NE(gc_comp, nullptr);
    EXPECT_EQ(gc_comp->directly_removed_objects, 1U);
    EXPECT_EQ(kasumi::transport::presence(storage, orphan_cid).value(),
              kasumi::transport::Presence::Absent);

    // Device B creates file with that exact content and syncs: reupload succeeds
    kasumi::test::write_text(f.local_b / "reupload.txt", reupload_text);
    const auto sync_b = kasumi::application::execute(request(Operation::Sync, f.env_b));
    ASSERT_TRUE(sync_b.has_value()) << sync_b.error().detail;
    const auto* comp_b = std::get_if<kasumi::application::SyncCompleted>(&sync_b->data);
    ASSERT_NE(comp_b, nullptr);
    EXPECT_EQ(comp_b->uploaded, 1U);

    // Device A syncs and receives the file
    ASSERT_TRUE(kasumi::application::execute(request(Operation::Sync, f.env_a)));
    EXPECT_TRUE(std::filesystem::exists(f.local_a / "reupload.txt"));
    EXPECT_EQ(kasumi::test::read_text(f.local_a / "reupload.txt"), reupload_text);
}

} // namespace
