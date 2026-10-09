#include "application/execute.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/profile.hpp"
#include "cli/app.hpp"
#include "core/hasher.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/physical_hash.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/clock.hpp"
#include "platform/profile_lock.hpp"
#include "runtime/vault.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <gtest/gtest.h>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace protocol = kasumi::application::history_storage::maintenance_protocol;
namespace history = kasumi::application::history_storage;
namespace transport = kasumi::transport;

struct CliResult {
    int code = 0;
    std::string output;
};

CliResult run_cli(std::vector<std::string> arguments) {
    std::vector<char*> argv;
    for (auto& argument : arguments) {
        argv.push_back(argument.data());
    }
    testing::internal::CaptureStdout();
    const auto code =
        kasumi::cli::run(static_cast<int>(argv.size()), argv.data());
    return {code, testing::internal::GetCapturedStdout()};
}

class ManualQuarantinePurgeContract : public testing::Test {
protected:
    kasumi::test::TempWorkspace workspace =
        kasumi::test::make_temp_workspace("manual-quarantine-purge");
    std::filesystem::path remote_dir =
        kasumi::test::workspace_path(workspace, "remote");
    kasumi::application::ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "kasumi")};
    kasumi::application::Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        remote_dir.string()};
    std::string master_hex = std::string(64, '9');
#if defined(_WIN32)
    kasumi::test::ScopedWindowsEnvironmentVariable windows_app_root{
        nullptr, kasumi::test::restore_windows_environment_variable};
#endif
    kasumi::test::ScopedEnvironmentVariable app_root{
        nullptr, kasumi::test::restore_environment_variable};
    kasumi::test::ScopedEnvironmentVariable master_key_environment{
        nullptr, kasumi::test::restore_environment_variable};
    kasumi::runtime::vault::KeyBytes key{};
    history::RemoteLayout layout;
    std::optional<transport::Transport> storage;
    std::size_t next_file = 0;

    void SetUp() override {
#if defined(_WIN32)
        windows_app_root = kasumi::test::scoped_windows_environment_variable(
            L"APPDATA", environment.app_data_dir.parent_path().wstring());
        app_root = kasumi::test::scoped_environment_variable(
            "APPDATA", environment.app_data_dir.parent_path().string());
#else
        app_root = kasumi::test::scoped_environment_variable(
            "XDG_CONFIG_HOME", environment.app_data_dir.parent_path().string());
#endif
        master_key_environment = kasumi::test::scoped_environment_variable(
            "KASUMI_MASTER_KEY", master_hex);
        ASSERT_TRUE(kasumi::application::create_profile(
            environment,
            profile,
            kasumi::application::MasterKeyHex{master_hex}));
        ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
        auto decoded = kasumi::runtime::vault::decode_hex(master_hex);
        ASSERT_TRUE(decoded.has_value());
        key = *decoded;
        layout = history::derive_remote_layout(key);
        auto opened = transport::open_transport(remote_dir.string());
        ASSERT_TRUE(opened.has_value());
        storage.emplace(std::move(*opened));
        ASSERT_TRUE(transport::initialize(*storage));
    }

    CliResult purge(std::vector<std::string> extra = {}) {
        std::vector<std::string> args{
            "kasumi", "gc", "purge-quarantine", "demo"};
        args.insert(args.end(), extra.begin(), extra.end());
        return run_cli(std::move(args));
    }

    CliResult confirmed_purge() {
        return purge({"--confirm-permanent-loss"});
    }

    void seed_history() {
        kasumi::test::write_text(profile.local_dir / "live.txt", "live");
        const auto synced = kasumi::application::execute(
            {kasumi::application::Request{kasumi::application::Operation::Sync,
                                          "demo"},
             kasumi::application::Credentials{
                 kasumi::application::NoCredentials{}},
             environment});
        ASSERT_TRUE(synced.has_value()) << synced.error().detail;
    }

    std::string content_id(std::string_view plaintext) const {
        return kasumi::crypto::content_identifier(
            key, kasumi::hasher::hash_string(plaintext));
    }

    std::filesystem::path encrypted_file(std::string_view plaintext) {
        const auto name = std::to_string(next_file++);
        const auto plain =
            kasumi::test::workspace_path(workspace, name + ".plain");
        const auto encrypted =
            kasumi::test::workspace_path(workspace, name + ".encrypted");
        kasumi::test::write_text(plain, plaintext);
        EXPECT_TRUE(kasumi::crypto::encrypt_file(plain, encrypted, key));
        return encrypted;
    }

    void put_object(std::string_view identifier, std::string_view plaintext) {
        EXPECT_TRUE(
            transport::put(*storage, encrypted_file(plaintext), identifier));
    }

    std::optional<protocol::QuarantineEntry>
    add_quarantine(std::string_view plaintext) {
        const auto original = content_id(plaintext);
        const auto quarantine =
            protocol::quarantine_identifier(layout, original);
        if (!quarantine) {
            ADD_FAILURE() << "invalid fixture quarantine identifier";
            return std::nullopt;
        }
        put_object(*quarantine, plaintext);
        auto now = kasumi::platform::clock::unix_seconds();
        if (!now) {
            ADD_FAILURE() << now.error();
            return std::nullopt;
        }
        auto recorded = protocol::record_quarantine(
            *storage,
            *quarantine,
            *now,
            key,
            kasumi::test::workspace_root(workspace));
        if (!recorded) {
            ADD_FAILURE() << recorded.error().detail;
            return std::nullopt;
        }
        return *recorded;
    }

    void prove_quarantine(std::vector<std::string> selected) {
        auto inventory = protocol::inventory_quarantine(
            *storage, key, kasumi::test::workspace_root(workspace));
        ASSERT_TRUE(inventory.has_value()) << inventory.error().detail;
        ASSERT_EQ(inventory->size(), selected.size());
        const auto now = kasumi::platform::clock::unix_seconds();
        ASSERT_TRUE(now.has_value());
        std::vector<std::string> actual;
        for (const auto& entry : *inventory) {
            ASSERT_TRUE(entry.quarantined_at.has_value());
            EXPECT_GE(*now, *entry.quarantined_at);
            EXPECT_LT(*now - *entry.quarantined_at,
                      protocol::quarantine_retention_seconds);
            const auto verified = protocol::verify_quarantine(
                *storage, entry, kasumi::test::workspace_root(workspace));
            ASSERT_TRUE(verified.has_value()) << verified.error().detail;
            EXPECT_TRUE(*verified);
            const auto original =
                transport::presence(*storage, entry.original_identifier);
            ASSERT_TRUE(original.has_value()) << original.error().message;
            EXPECT_EQ(*original, transport::Presence::Absent);
            actual.push_back(entry.quarantine_identifier);
        }
        std::ranges::sort(actual);
        std::ranges::sort(selected);
        EXPECT_EQ(actual, selected);
    }

    std::map<std::string, std::string> remote_snapshot() {
        std::map<std::string, std::string> result;
        const auto listed = transport::list(*storage);
        if (!listed) {
            ADD_FAILURE() << listed.error().message;
            return result;
        }
        for (const auto& identifier : *listed) {
            const auto downloaded = kasumi::test::workspace_path(
                workspace, "snapshot-" + std::to_string(next_file++));
            const auto fetched =
                transport::get(*storage, identifier, downloaded);
            if (!fetched) {
                ADD_FAILURE() << identifier << ": " << fetched.error().message;
                continue;
            }
            const auto physical =
                kasumi::crypto::physical::hash_file(downloaded, "sha256");
            if (!physical) {
                ADD_FAILURE() << identifier << ": " << physical.error();
                continue;
            }
            result.emplace(identifier, *physical);
        }
        return result;
    }
};

TEST_F(
    ManualQuarantinePurgeContract,
    ManualQuarantinePurgeRemovesAuthenticatedYoungEntriesWithExplicitAuthority) {
    seed_history();
    const auto first = add_quarantine("young-one");
    const auto second = add_quarantine("young-two");
    ASSERT_TRUE(first && second);
    prove_quarantine(
        {first->quarantine_identifier, second->quarantine_identifier});
    const auto unrelated = content_id("unrelated-orphan");
    put_object(unrelated, "unrelated-orphan");
    const auto unsynced = profile.local_dir / "unsynced.txt";
    kasumi::test::write_text(unsynced, "local-only");
    const auto before = remote_snapshot();

    const auto result = confirmed_purge();
    EXPECT_EQ(result.code, 0) << result.output;
    auto expected = before;
    for (const auto& entry : {*first, *second}) {
        expected.erase(entry.quarantine_identifier);
        expected.erase(entry.metadata_identifier);
    }
    EXPECT_EQ(remote_snapshot(), expected);
    EXPECT_TRUE(expected.contains(unrelated));
    EXPECT_EQ(kasumi::test::read_text(unsynced), "local-only");
}

TEST_F(ManualQuarantinePurgeContract,
       MissingConfirmationAndMalformedArgumentsPreserveObjects) {
    const auto entry = add_quarantine("young-one");
    ASSERT_TRUE(entry);
    prove_quarantine({entry->quarantine_identifier});
    const auto before = remote_snapshot();
    const std::vector<std::vector<std::string>> rejected{
        {"kasumi", "gc", "purge-quarantine", "demo"},
        {"kasumi", "gc", "purge-quarantine", "demo", "--unknown"},
        {"kasumi",
         "gc",
         "purge-quarantine",
         "demo",
         "--confirm-permanent-loss",
         "extra"},
        {"kasumi", "gc", "purge-quarantine", "", "--confirm-permanent-loss"},
    };
    for (const auto& args : rejected) {
        SCOPED_TRACE(args.back());
        EXPECT_NE(run_cli(args).code, 0);
        EXPECT_EQ(remote_snapshot(), before);
    }
}

TEST_F(ManualQuarantinePurgeContract, WrongVaultCredentialsPreserveQuarantine) {
    const auto entry = add_quarantine("young-one");
    ASSERT_TRUE(entry);
    prove_quarantine({entry->quarantine_identifier});
    const auto before = remote_snapshot();
    [[maybe_unused]] auto wrong_key = kasumi::test::scoped_environment_variable(
        "KASUMI_MASTER_KEY", std::string(64, 'a'));
    const auto ordinary = run_cli({"kasumi", "gc", "demo"});
    EXPECT_NE(ordinary.code, 0);
    EXPECT_NE(ordinary.output.find("credential"), std::string::npos);
    const auto result = confirmed_purge();
    EXPECT_NE(result.code, 0);
    EXPECT_EQ(remote_snapshot(), before);
}

TEST_F(ManualQuarantinePurgeContract, OrdinaryGcKeepsYoungQuarantine) {
    seed_history();
    const auto entry = add_quarantine("young-one");
    ASSERT_TRUE(entry);
    prove_quarantine({entry->quarantine_identifier});
    const auto before = remote_snapshot();
    const auto result = run_cli({"kasumi", "gc", "demo"});
    ASSERT_EQ(result.code, 0) << result.output;
    EXPECT_EQ(remote_snapshot(), before);
}

TEST_F(ManualQuarantinePurgeContract,
       ExplicitPurgeCanRemoveReachableQuarantineWithoutEditingHistory) {
    seed_history();
    const auto original = content_id("live");
    const auto quarantine = protocol::quarantine_identifier(layout, original);
    ASSERT_TRUE(quarantine);
    const auto copy = kasumi::test::workspace_path(workspace, "reachable.copy");
    ASSERT_TRUE(transport::get(*storage, original, copy));
    ASSERT_TRUE(transport::put(*storage, copy, *quarantine));
    ASSERT_EQ(transport::remove(*storage, original).value(),
              transport::Removal::Removed);
    const auto now = kasumi::platform::clock::unix_seconds();
    ASSERT_TRUE(now.has_value());
    const auto recorded =
        protocol::record_quarantine(*storage,
                                    *quarantine,
                                    *now,
                                    key,
                                    kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(recorded.has_value()) << recorded.error().detail;
    prove_quarantine({*quarantine});
    const auto before = remote_snapshot();

    const auto result = confirmed_purge();
    EXPECT_EQ(result.code, 0) << result.output;
    auto expected = before;
    expected.erase(recorded->quarantine_identifier);
    expected.erase(recorded->metadata_identifier);
    EXPECT_EQ(remote_snapshot(), expected);
    EXPECT_FALSE(expected.contains(original));
}

TEST_F(ManualQuarantinePurgeContract, OrdinaryGcRestoresReachableQuarantine) {
    seed_history();
    const auto original = content_id("live");
    const auto quarantine = protocol::quarantine_identifier(layout, original);
    ASSERT_TRUE(quarantine);
    const auto copy = kasumi::test::workspace_path(workspace, "reachable.copy");
    ASSERT_TRUE(transport::get(*storage, original, copy));
    ASSERT_TRUE(transport::put(*storage, copy, *quarantine));
    ASSERT_EQ(transport::remove(*storage, original).value(),
              transport::Removal::Removed);
    const auto now = kasumi::platform::clock::unix_seconds();
    ASSERT_TRUE(now.has_value());
    ASSERT_TRUE(
        protocol::record_quarantine(*storage,
                                    *quarantine,
                                    *now,
                                    key,
                                    kasumi::test::workspace_root(workspace)));
    prove_quarantine({*quarantine});

    const auto result = run_cli({"kasumi", "gc", "demo"});
    ASSERT_EQ(result.code, 0) << result.output;
    EXPECT_EQ(transport::presence(*storage, original).value(),
              transport::Presence::Present);
    EXPECT_EQ(transport::presence(*storage, *quarantine).value(),
              transport::Presence::Present);
}

TEST_F(ManualQuarantinePurgeContract, InvalidQuarantineInventoryFailsClosed) {
    const auto entry = add_quarantine("young-one");
    const auto other = add_quarantine("young-two");
    ASSERT_TRUE(entry && other);
    prove_quarantine(
        {entry->quarantine_identifier, other->quarantine_identifier});
    const auto metadata_copy =
        kasumi::test::workspace_path(workspace, "metadata.copy");
    ASSERT_TRUE(
        transport::get(*storage, entry->metadata_identifier, metadata_copy));
    auto bytes = kasumi::test::read_binary(metadata_copy);
    ASSERT_FALSE(bytes.empty());
    bytes.front() ^= std::byte{1};
    kasumi::test::write_binary(metadata_copy, bytes);
    ASSERT_TRUE(
        transport::put(*storage, metadata_copy, entry->metadata_identifier));
    EXPECT_FALSE(protocol::inventory_quarantine(
        *storage, key, kasumi::test::workspace_root(workspace)));
    const auto before = remote_snapshot();
    const auto result = confirmed_purge();
    EXPECT_NE(result.code, 0);
    EXPECT_EQ(remote_snapshot(), before);
}

TEST_F(ManualQuarantinePurgeContract, MissingMetadataFailsClosed) {
    const auto entry = add_quarantine("young-one");
    const auto other = add_quarantine("young-two");
    ASSERT_TRUE(entry && other);
    prove_quarantine(
        {entry->quarantine_identifier, other->quarantine_identifier});
    ASSERT_EQ(transport::remove(*storage, entry->metadata_identifier).value(),
              transport::Removal::Removed);
    const auto incomplete = protocol::inventory_quarantine(
        *storage, key, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(incomplete.has_value()) << incomplete.error().detail;
    const auto missing =
        std::ranges::find_if(*incomplete, [&](const auto& value) {
            return value.quarantine_identifier == entry->quarantine_identifier;
        });
    ASSERT_NE(missing, incomplete->end());
    EXPECT_FALSE(missing->quarantined_at.has_value());
    const auto before = remote_snapshot();
    EXPECT_NE(confirmed_purge().code, 0);
    EXPECT_EQ(remote_snapshot(), before);
}

TEST_F(ManualQuarantinePurgeContract, MetadataWithoutPayloadFailsClosed) {
    const auto entry = add_quarantine("young-one");
    ASSERT_TRUE(entry);
    prove_quarantine({entry->quarantine_identifier});
    ASSERT_EQ(transport::remove(*storage, entry->quarantine_identifier).value(),
              transport::Removal::Removed);
    EXPECT_FALSE(protocol::inventory_quarantine(
        *storage, key, kasumi::test::workspace_root(workspace)));
    const auto before = remote_snapshot();
    EXPECT_NE(confirmed_purge().code, 0);
    EXPECT_EQ(remote_snapshot(), before);
}

TEST_F(ManualQuarantinePurgeContract,
       MetadataCopiedToUnexpectedPayloadFailsClosed) {
    const auto first = add_quarantine("young-one");
    const auto second = add_quarantine("young-two");
    ASSERT_TRUE(first && second);
    prove_quarantine(
        {first->quarantine_identifier, second->quarantine_identifier});
    const auto copy = kasumi::test::workspace_path(workspace, "wrong.meta");
    ASSERT_TRUE(transport::get(*storage, first->metadata_identifier, copy));
    ASSERT_TRUE(transport::put(*storage, copy, second->metadata_identifier));
    const auto mismatched = protocol::inventory_quarantine(
        *storage, key, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(mismatched.has_value()) << mismatched.error().detail;
    const auto target =
        std::ranges::find_if(*mismatched, [&](const auto& value) {
            return value.quarantine_identifier == second->quarantine_identifier;
        });
    ASSERT_NE(target, mismatched->end());
    const auto verified = protocol::verify_quarantine(
        *storage, *target, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(verified.has_value()) << verified.error().detail;
    EXPECT_FALSE(*verified);
    const auto before = remote_snapshot();
    EXPECT_NE(confirmed_purge().code, 0);
    EXPECT_EQ(remote_snapshot(), before);
}

TEST_F(ManualQuarantinePurgeContract, PhysicalHashMismatchFailsClosed) {
    const auto entry = add_quarantine("young-one");
    ASSERT_TRUE(entry);
    prove_quarantine({entry->quarantine_identifier});
    put_object(entry->quarantine_identifier, "replacement");
    const auto mismatched = protocol::inventory_quarantine(
        *storage, key, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(mismatched.has_value()) << mismatched.error().detail;
    ASSERT_EQ(mismatched->size(), 1U);
    const auto verified = protocol::verify_quarantine(
        *storage, mismatched->front(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(verified.has_value()) << verified.error().detail;
    EXPECT_FALSE(*verified);
    const auto before = remote_snapshot();
    EXPECT_NE(confirmed_purge().code, 0);
    EXPECT_EQ(remote_snapshot(), before);
}

TEST_F(ManualQuarantinePurgeContract,
       MalformedQuarantineIdentifierFailsClosed) {
    const auto entry = add_quarantine("young-one");
    ASSERT_TRUE(entry);
    prove_quarantine({entry->quarantine_identifier});
    put_object(layout.quarantine_prefix + "malformed", "foreign");
    EXPECT_FALSE(protocol::inventory_quarantine(
        *storage, key, kasumi::test::workspace_root(workspace)));
    const auto before = remote_snapshot();
    EXPECT_NE(confirmed_purge().code, 0);
    EXPECT_EQ(remote_snapshot(), before);
}

TEST_F(ManualQuarantinePurgeContract,
       InconsistentDuplicateMetadataFailsClosed) {
    const auto entry = add_quarantine("young-one");
    ASSERT_TRUE(entry);
    prove_quarantine({entry->quarantine_identifier});
    const auto copy = kasumi::test::workspace_path(workspace, "duplicate.meta");
    ASSERT_TRUE(transport::get(*storage, entry->metadata_identifier, copy));
    ASSERT_TRUE(
        transport::put(*storage, copy, entry->metadata_identifier + ".meta"));
    EXPECT_FALSE(protocol::inventory_quarantine(
        *storage, key, kasumi::test::workspace_root(workspace)));
    const auto before = remote_snapshot();
    EXPECT_NE(confirmed_purge().code, 0);
    EXPECT_EQ(remote_snapshot(), before);
}

TEST_F(ManualQuarantinePurgeContract, ValidEpochObjectsSurvive) {
    seed_history();
    const auto entry = add_quarantine("young-one");
    ASSERT_TRUE(entry);
    prove_quarantine({entry->quarantine_identifier});
    const auto reachability = history::inventory_reachability(
        *storage, key, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(reachability.has_value()) << reachability.error().detail;
    ASSERT_FALSE(reachability->valid_epochs.empty());
    const auto chain = history::epoch::load_chain(
        *storage, key, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(chain.has_value()) << chain.error().detail;
    ASSERT_FALSE(chain->empty());
    const auto epoch_id =
        history::epoch::object_identifier(layout, chain->back().reference);
    ASSERT_TRUE(epoch_id.has_value());
    EXPECT_NE(std::ranges::find(reachability->valid_epochs, *epoch_id),
              reachability->valid_epochs.end());
    const auto before = remote_snapshot();
    ASSERT_TRUE(before.contains(*epoch_id));

    const auto result = confirmed_purge();
    EXPECT_EQ(result.code, 0) << result.output;
    auto expected = before;
    expected.erase(entry->quarantine_identifier);
    expected.erase(entry->metadata_identifier);
    EXPECT_EQ(remote_snapshot(), expected);
}

TEST_F(ManualQuarantinePurgeContract, ForeignNamespaceObjectsSurvive) {
    seed_history();
    const auto entry = add_quarantine("young-one");
    ASSERT_TRUE(entry);
    prove_quarantine({entry->quarantine_identifier});
    const auto foreign_key =
        kasumi::runtime::vault::decode_hex(std::string(64, 'a'));
    ASSERT_TRUE(foreign_key.has_value());
    const auto foreign_layout = history::derive_remote_layout(*foreign_key);
    const auto foreign_quarantine = protocol::quarantine_identifier(
        foreign_layout, content_id("foreign-quarantine"));
    ASSERT_TRUE(foreign_quarantine.has_value());
    put_object(*foreign_quarantine, "foreign-quarantine");
    put_object("foreign/unrelated-object", "foreign");
    const auto before = remote_snapshot();
    ASSERT_TRUE(before.contains(*foreign_quarantine));

    const auto result = confirmed_purge();
    EXPECT_EQ(result.code, 0) << result.output;
    const auto after = remote_snapshot();
    ASSERT_TRUE(after.contains(*foreign_quarantine));
    EXPECT_EQ(after.at(*foreign_quarantine), before.at(*foreign_quarantine));
    auto expected = before;
    expected.erase(entry->quarantine_identifier);
    expected.erase(entry->metadata_identifier);
    EXPECT_EQ(after, expected);
}

TEST_F(ManualQuarantinePurgeContract, ActiveAndAbandonedWritersBlockPurge) {
    const auto entry = add_quarantine("young-one");
    ASSERT_TRUE(entry);
    prove_quarantine({entry->quarantine_identifier});
    auto writer = protocol::register_writer(
        *storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;
    const auto active_writers = protocol::active_writers(*storage, layout);
    ASSERT_TRUE(active_writers.has_value()) << active_writers.error().detail;
    EXPECT_EQ(active_writers->size(), 1U);
    const auto active_before = remote_snapshot();
    const auto active = confirmed_purge();
    EXPECT_NE(active.code, 0);
    EXPECT_EQ(remote_snapshot(), active_before);
    ASSERT_TRUE(protocol::release_registration(*writer));

    const auto abandoned = layout.writers_prefix + std::string(32, 'a');
    put_object(abandoned, "abandoned-writer");
    const auto abandoned_writers = protocol::active_writers(*storage, layout);
    ASSERT_TRUE(abandoned_writers.has_value())
        << abandoned_writers.error().detail;
    EXPECT_EQ(abandoned_writers->size(), 1U);
    const auto abandoned_before = remote_snapshot();
    const auto result = confirmed_purge();
    EXPECT_NE(result.code, 0);
    EXPECT_EQ(remote_snapshot(), abandoned_before);
}

TEST_F(ManualQuarantinePurgeContract, ExistingBarrierBlocksPurge) {
    const auto entry = add_quarantine("young-one");
    ASSERT_TRUE(entry);
    prove_quarantine({entry->quarantine_identifier});
    auto barrier = protocol::establish_barrier(
        *storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(barrier.has_value()) << barrier.error().detail;
    ASSERT_TRUE(protocol::verify_registration(*barrier));
    const auto before = remote_snapshot();
    const auto result = confirmed_purge();
    EXPECT_NE(result.code, 0);
    EXPECT_EQ(remote_snapshot(), before);
    ASSERT_TRUE(protocol::release_registration(*barrier));
}

TEST_F(ManualQuarantinePurgeContract,
       EmptyQuarantineSucceedsWithoutDeletingObjects) {
    seed_history();
    const auto before = remote_snapshot();
    const auto result = confirmed_purge();
    EXPECT_EQ(result.code, 0) << result.output;
    EXPECT_EQ(remote_snapshot(), before);
    EXPECT_NE(result.output.find('0'), std::string::npos);
}

class ManualQuarantineRepairContract : public ManualQuarantinePurgeContract {
protected:
    CliResult repair(std::vector<std::string> extra = {}) {
        std::vector<std::string> args{
            "kasumi", "gc", "repair-quarantine", "demo"};
        args.insert(args.end(), extra.begin(), extra.end());
        return run_cli(std::move(args));
    }

    CliResult confirmed_repair() {
        return repair({"--confirm-permanent-loss"});
    }
};

class ManualWriterRemovalContract : public ManualQuarantinePurgeContract {
protected:
    CliResult remove_writer(std::string identifier,
                            std::string language = "en") {
        return run_cli({"kasumi",
                        "--lang",
                        std::move(language),
                        "gc",
                        "remove-writer",
                        "demo",
                        std::move(identifier)});
    }
};

TEST_F(ManualWriterRemovalContract,
       RemovesOnlyTheSelectedWriterAndLeavesNormalGcBlocked) {
    const auto selected = layout.writers_prefix + std::string(32, 'a');
    const auto other = layout.writers_prefix + std::string(32, 'b');
    put_object(selected, "selected writer");
    put_object(other, "other writer");
    put_object("unrelated/object", "unrelated");
    auto expected = remote_snapshot();
    expected.erase(selected);

    const auto result = remove_writer(selected);
    ASSERT_EQ(result.code, 0) << result.output;
    EXPECT_NE(
        result.output.find("cannot determine whether this writer's process"),
        std::string::npos);
    EXPECT_NE(result.output.find(
                  "Verify that no Sync or maintenance operation is active"),
              std::string::npos);
    EXPECT_NE(result.output.find("Removed writer marker: " + selected),
              std::string::npos);
    EXPECT_EQ(remote_snapshot(), expected);

    const auto gc = run_cli({"kasumi", "gc", "demo"});
    EXPECT_NE(gc.code, 0);
    EXPECT_EQ(remote_snapshot(), expected);
}

TEST_F(ManualWriterRemovalContract,
       RejectsMissingAndForeignWriterIdentifiersWithoutMutatingStorage) {
    const auto missing = layout.writers_prefix + std::string(32, 'a');
    const auto foreign_key =
        kasumi::runtime::vault::decode_hex(std::string(64, 'a'));
    ASSERT_TRUE(foreign_key.has_value());
    const auto foreign =
        history::derive_remote_layout(*foreign_key).writers_prefix +
        std::string(32, 'b');
    const auto before = remote_snapshot();

    EXPECT_NE(remove_writer("../unrelated/object").code, 0);
    EXPECT_NE(remove_writer(missing).code, 0);
    EXPECT_NE(remove_writer(foreign).code, 0);
    EXPECT_EQ(remote_snapshot(), before);
}

TEST_F(ManualWriterRemovalContract, NeverRemovesAnExistingGcBarrier) {
    const auto selected = layout.writers_prefix + std::string(32, 'a');
    put_object(selected, "selected writer");
    put_object(layout.barrier_identifier, "other operation barrier");
    const auto before = remote_snapshot();

    const auto result = remove_writer(selected);
    EXPECT_NE(result.code, 0) << result.output;
    EXPECT_NE(result.output.find("maintenance barrier is present"),
              std::string::npos)
        << result.output;
    EXPECT_EQ(remote_snapshot(), before);
}

TEST_F(ManualWriterRemovalContract,
       RecoversFromAnAbandonedRegisteredWriterSoGcCanRun) {
    seed_history();
    auto registration = protocol::register_writer(
        *storage, layout, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(registration.has_value()) << registration.error().detail;
    const auto identifier = registration->identifier;
    // Deliberately do not release the registration: this is the remote state
    // left behind when Sync is terminated unexpectedly.
    const auto before = remote_snapshot();
    ASSERT_TRUE(before.contains(identifier));

    const auto blocked = run_cli({"kasumi", "gc", "demo"});
    EXPECT_NE(blocked.code, 0) << blocked.output;
    EXPECT_EQ(remote_snapshot(), before);

    const auto removed = remove_writer(identifier);
    ASSERT_EQ(removed.code, 0) << removed.output;
    auto expected = before;
    expected.erase(identifier);
    EXPECT_EQ(remote_snapshot(), expected);

    const auto collected = run_cli({"kasumi", "gc", "demo"});
    EXPECT_EQ(collected.code, 0) << collected.output;
    const auto writers = protocol::active_writers(*storage, layout);
    ASSERT_TRUE(writers.has_value()) << writers.error().detail;
    EXPECT_TRUE(writers->empty());
    EXPECT_EQ(remote_snapshot(), expected);
}

TEST_F(ManualWriterRemovalContract, RespectsTheLocalProfileLock) {
    const auto selected = layout.writers_prefix + std::string(32, 'a');
    put_object(selected, "selected writer");
    const auto before = remote_snapshot();
    auto acquired = kasumi::platform::acquire_profile_lock(
        environment.app_data_dir / "profile-demo.lock");
    ASSERT_TRUE(acquired.has_value()) << acquired.error();
    auto held = *acquired;

    const auto blocked = remove_writer(selected);
    EXPECT_NE(blocked.code, 0);
    EXPECT_EQ(remote_snapshot(), before);

    kasumi::platform::release_profile_lock(held);
    const auto removed = remove_writer(selected);
    EXPECT_EQ(removed.code, 0) << removed.output;
}

TEST_F(ManualWriterRemovalContract, WarningAndSuccessAreLocalized) {
    const auto selected = layout.writers_prefix + std::string(32, 'a');
    put_object(selected, "selected writer");

    const auto result = remove_writer(selected, "pt-BR");
    ASSERT_EQ(result.code, 0) << result.output;
    EXPECT_NE(result.output.find("não consegue determinar se o processo"),
              std::string::npos);
    EXPECT_NE(result.output.find(
                  "Verifique se não há Sync ou operação de manutenção"),
              std::string::npos);
    EXPECT_NE(result.output.find("Marker de writer removido: " + selected),
              std::string::npos);
}

TEST_F(ManualQuarantineRepairContract,
       MissingConfirmationAndMalformedArgumentsPreserveObjects) {
    const auto entry = add_quarantine("young-one");
    ASSERT_TRUE(entry);
    prove_quarantine({entry->quarantine_identifier});
    const auto before = remote_snapshot();
    const std::vector<std::vector<std::string>> rejected{
        {"kasumi", "gc", "repair-quarantine", "demo"},
        {"kasumi", "gc", "repair-quarantine", "demo", "--unknown"},
        {"kasumi",
         "gc",
         "repair-quarantine",
         "demo",
         "--confirm-permanent-loss",
         "extra"},
        {"kasumi", "gc", "repair-quarantine", "", "--confirm-permanent-loss"},
    };
    for (const auto& args : rejected) {
        SCOPED_TRACE(args.back());
        EXPECT_NE(run_cli(args).code, 0);
        EXPECT_EQ(remote_snapshot(), before);
    }
}

TEST_F(ManualQuarantineRepairContract,
       RepairRemovesAuthenticatedMetadataWhenPayloadAbsent) {
    seed_history();
    const auto entry = add_quarantine("young-one");
    ASSERT_TRUE(entry);
    prove_quarantine({entry->quarantine_identifier});

    ASSERT_EQ(transport::remove(*storage, entry->quarantine_identifier).value(),
              transport::Removal::Removed);
    const auto before = remote_snapshot();
    ASSERT_TRUE(before.contains(entry->metadata_identifier));
    ASSERT_FALSE(before.contains(entry->quarantine_identifier));

    const auto result = confirmed_repair();
    EXPECT_EQ(result.code, 0) << result.output;
    auto expected = before;
    expected.erase(entry->metadata_identifier);
    EXPECT_EQ(remote_snapshot(), expected);
}

} // namespace
