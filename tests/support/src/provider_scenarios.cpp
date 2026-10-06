#include "kasumi/test/provider_scenarios.hpp"

#include "application/execute.hpp"
#include "application/observation/history.hpp"
#include "application/request.hpp"
#include "core/node.hpp"
#include "kasumi/test/filesystem.hpp"
#include "platform/path.hpp"
#include "platform/metadata.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>

namespace kasumi::test::scenarios {
namespace {

std::expected<void, std::string>
ensure_directory(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::create_directories(path, error);
    if (error) {
        return std::unexpected(error.message());
    }
    return {};
}

std::expected<state_storage::StoredState, std::string>
load_state(const SyncScenarioClient& client) {
    auto runtime = runtime::resolve(client.environment.app_data_dir,
                                    client.profile,
                                    runtime::AccessMode::ReadOnly);
    if (!runtime) {
        return std::unexpected(runtime.error().detail);
    }
    auto state = state_storage::load_state(runtime->database_path);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (!state->has_value()) {
        return std::unexpected("client has no accepted state");
    }
    return std::move(**state);
}

std::expected<application::observation::history::StorageView, std::string>
observe_remote(const TwoClientSyncScenario& scenario,
               std::string_view label) {
    auto storage = transport::open_transport(scenario.remote_locator);
    if (!storage) {
        return std::unexpected(storage.error().message);
    }
    const auto observation_root = scenario.scratch_root / "observations" /
                                  platform::path::from_utf8(label);
    if (auto created = ensure_directory(observation_root); !created) {
        return std::unexpected(created.error());
    }
    std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    key.fill(0x77U);
    auto observed = application::observation::history::observe(
        *storage, key, observation_root, false);
    if (!observed) {
        return std::unexpected(observed.error().detail);
    }
    return std::move(*observed);
}

std::expected<void, std::string>
sync_client(const SyncScenarioClient& client) {
    auto result = sync(client.environment, client.profile);
    if (!result) {
        return std::unexpected(client.profile + ": " + result.error());
    }
    return {};
}

std::expected<void, std::string>
write_local(const SyncScenarioClient& client,
            std::string_view relative,
            std::string_view contents) {
    const auto path = client.local_root / platform::path::from_utf8(relative);
    if (auto created = ensure_directory(path.parent_path()); !created) {
        return created;
    }
    write_text(path, contents);
    return {};
}

std::expected<void, std::string>
expect_file(const SyncScenarioClient& client,
            std::string_view relative,
            std::string_view contents) {
    const auto path = client.local_root / platform::path::from_utf8(relative);
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error) || error) {
        return std::unexpected("expected file is missing: " +
                               std::string{relative});
    }
    if (read_text(path) != contents) {
        return std::unexpected("file contents differ: " +
                               std::string{relative});
    }
    return {};
}

std::expected<void, std::string>
expect_absent(const SyncScenarioClient& client, std::string_view relative) {
    std::error_code error;
    const auto path = client.local_root / platform::path::from_utf8(relative);
    const bool exists = std::filesystem::exists(path, error);
    if (error || exists) {
        return std::unexpected("deleted file remains locally: " +
                               std::string{relative});
    }
    return {};
}

std::expected<void, std::string>
expect_converged(const TwoClientSyncScenario& scenario,
                 std::string_view observation_label) {
    auto observed = observe_remote(scenario, observation_label);
    if (!observed) {
        return std::unexpected(observed.error());
    }
    if (observed->logical_heads.size() != 1U) {
        return std::unexpected("remote history is not converged to one head");
    }
    auto state_a = load_state(scenario.a);
    auto state_b = load_state(scenario.b);
    if (!state_a || !state_b) {
        return std::unexpected(!state_a ? state_a.error() : state_b.error());
    }
    for (const auto* state : {&*state_a, &*state_b}) {
        if (state->commit_id != observed->logical_heads.front() ||
            state->tree != observed->effective_tree ||
            !state->pending_materializations.empty()) {
            return std::unexpected(
                "client accepted state or pending materializations did not converge");
        }
    }
    if (snapshot_tree(scenario.a.local_root) !=
        snapshot_tree(scenario.b.local_root)) {
        return std::unexpected("client local trees differ after sync");
    }
    const auto no_op_a = no_op_sync(scenario.a.environment, scenario.a.profile);
    const auto no_op_b = no_op_sync(scenario.b.environment, scenario.b.profile);
    if (!no_op_a || !no_op_b || !*no_op_a || !*no_op_b) {
        return std::unexpected("converged client did not remain a full no-op");
    }
    return {};
}

std::expected<void, std::string>
remove_local(const SyncScenarioClient& client, std::string_view relative) {
    std::error_code error;
    const auto path = client.local_root / platform::path::from_utf8(relative);
    if (!std::filesystem::remove(path, error) || error) {
        return std::unexpected("could not delete local file: " +
                               std::string{relative});
    }
    return {};
}

} // namespace

std::expected<void, std::string>
sync(const application::ExecutionEnvironment& environment,
     std::string_view profile) {
    auto result = application::execute(
        {application::Request{application::Operation::Sync,
                              std::string{profile}},
         application::Credentials{application::NoCredentials{}},
         environment});
    if (!result) {
        return std::unexpected(result.error().detail);
    }
    return {};
}

std::expected<void, std::string>
publish_seed_files(const application::ExecutionEnvironment& environment,
                   std::string_view profile,
                   const std::filesystem::path& local_root,
                   const std::vector<SeedFile>& files) {
    if (auto created = ensure_directory(local_root); !created) {
        return created;
    }
    for (const auto& [relative, contents] : files) {
        const auto target = local_root / platform::path::from_utf8(relative);
        if (auto created = ensure_directory(target.parent_path()); !created) {
            return created;
        }
        write_text(target, contents);
    }
    return sync(environment, profile);
}

std::expected<void, std::string>
materialize_files(const application::ExecutionEnvironment& environment,
                  std::string_view profile,
                  const std::filesystem::path& local_root,
                  const std::vector<SeedFile>& files) {
    auto synchronized = sync(environment, profile);
    if (!synchronized) {
        return synchronized;
    }
    for (const auto& [relative, contents] : files) {
        const auto target = local_root / platform::path::from_utf8(relative);
        std::error_code error;
        if (!std::filesystem::is_regular_file(target, error) || error) {
            return std::unexpected("materialized file is missing: " + relative);
        }
        if (read_text(target) != contents) {
            return std::unexpected("materialized bytes differ: " + relative);
        }
    }
    return {};
}

std::expected<bool, std::string>
no_op_sync(const application::ExecutionEnvironment& environment,
           std::string_view profile) {
    auto result = application::execute(
        {application::Request{application::Operation::Sync,
                              std::string{profile}},
         application::Credentials{application::NoCredentials{}},
         environment});
    if (!result) {
        return std::unexpected(result.error().detail);
    }
    const auto* summary =
        std::get_if<application::SyncCompleted>(&result->data);
    if (summary == nullptr) {
        return std::unexpected("sync did not return SyncCompleted");
    }
    return result->operation == application::Operation::Sync &&
           !summary->published && !summary->partial &&
           summary->pending_paths.empty();
}

std::expected<void, std::string>
bidirectional_update(const TwoClientSyncScenario& scenario) {
    for (const auto& [path, contents] :
         {SeedFile{"update-x.txt", "X1"},
          SeedFile{"update-y.txt", "Y1"},
          SeedFile{"update-keep.txt", "KEEP"}}) {
        if (auto written = write_local(scenario.a, path, contents); !written) {
            return written;
        }
    }
    if (auto result = sync_client(scenario.a); !result) {
        return result;
    }
    if (auto result = sync_client(scenario.b); !result) {
        return result;
    }
    for (const auto& client : {scenario.a, scenario.b}) {
        for (const auto& [path, contents] :
             {SeedFile{"update-x.txt", "X1"},
              SeedFile{"update-y.txt", "Y1"},
              SeedFile{"update-keep.txt", "KEEP"}}) {
            if (auto valid = expect_file(client, path, contents); !valid) {
                return valid;
            }
        }
    }

    if (auto written = write_local(scenario.a, "update-x.txt", "X2");
        !written) {
        return written;
    }
    if (auto result = sync_client(scenario.a); !result) {
        return result;
    }
    if (auto result = sync_client(scenario.b); !result) {
        return result;
    }
    if (auto valid = expect_file(scenario.b, "update-x.txt", "X2"); !valid) {
        return valid;
    }

    if (auto written = write_local(scenario.b, "update-y.txt", "Y2");
        !written) {
        return written;
    }
    if (auto result = sync_client(scenario.b); !result) {
        return result;
    }
    if (auto result = sync_client(scenario.a); !result) {
        return result;
    }
    for (const auto& client : {scenario.a, scenario.b}) {
        for (const auto& [path, contents] :
             {SeedFile{"update-x.txt", "X2"},
              SeedFile{"update-y.txt", "Y2"},
              SeedFile{"update-keep.txt", "KEEP"}}) {
            if (auto valid = expect_file(client, path, contents); !valid) {
                return valid;
            }
        }
    }
    return expect_converged(scenario, "bidirectional-update");
}

std::expected<void, std::string>
logical_delete(const TwoClientSyncScenario& scenario) {
    const std::vector<SeedFile> seed{
        {"delete-a.txt", "A"},
        {"delete-b.txt", "B"},
        {"delete-c.txt", "C"},
        {"delete-keep.txt", "KEEP"},
    };
    auto seeded = publish_seed_files(scenario.a.environment,
                                     scenario.a.profile,
                                     scenario.a.local_root,
                                     seed);
    if (!seeded) {
        return seeded;
    }
    auto materialized = materialize_files(scenario.b.environment,
                                          scenario.b.profile,
                                          scenario.b.local_root,
                                          seed);
    if (!materialized) {
        return materialized;
    }
    for (const auto path : {"delete-a.txt", "delete-b.txt"}) {
        if (auto removed = remove_local(scenario.b, path); !removed) {
            return removed;
        }
    }
    if (auto result = sync_client(scenario.b); !result) {
        return result;
    }
    auto observed = observe_remote(scenario, "logical-delete-first");
    if (!observed) {
        return std::unexpected(observed.error());
    }
    if (find_row(observed->effective_tree, "delete-a.txt") != nullptr ||
        find_row(observed->effective_tree, "delete-b.txt") != nullptr) {
        return std::unexpected("logical delete remains in remote tree");
    }
    if (auto result = sync_client(scenario.a); !result) {
        return result;
    }
    for (const auto* client : {&scenario.a, &scenario.b}) {
        if (auto absent = expect_absent(*client, "delete-a.txt"); !absent) {
            return absent;
        }
        if (auto absent = expect_absent(*client, "delete-b.txt"); !absent) {
            return absent;
        }
        if (auto preserved = expect_file(*client, "delete-keep.txt", "KEEP");
            !preserved) {
            return preserved;
        }
    }
    for (const auto path : {"delete-c.txt", "delete-keep.txt"}) {
        if (auto removed = remove_local(scenario.b, path); !removed) {
            return removed;
        }
    }
    if (auto result = sync_client(scenario.b); !result) {
        return result;
    }
    if (auto result = sync_client(scenario.a); !result) {
        return result;
    }
    return expect_converged(scenario, "logical-delete-final");
}

std::expected<void, std::string>
two_client_conflict(const TwoClientSyncScenario& scenario) {
    if (auto written = write_local(scenario.a, "conflict-file.txt", "BASE");
        !written) {
        return written;
    }
    if (auto result = sync_client(scenario.a); !result) {
        return result;
    }
    if (auto result = sync_client(scenario.b); !result) {
        return result;
    }
    if (auto written = write_local(scenario.a, "conflict-file.txt", "A-V2");
        !written) {
        return written;
    }
    if (auto written = write_local(scenario.b, "conflict-file.txt", "B-V2");
        !written) {
        return written;
    }
    const auto timestamp = std::filesystem::file_time_type::clock::now();
    for (const auto& [client, offset] :
         {std::pair{&scenario.a, std::chrono::hours{2}},
          std::pair{&scenario.b, std::chrono::hours{1}}}) {
        const auto path = client->local_root /
                          platform::path::from_utf8("conflict-file.txt");
        auto set = platform::metadata::set_last_write_time(path,
                                                           timestamp + offset);
        if (!set) {
            return std::unexpected(set.error());
        }
    }
    if (auto result = sync_client(scenario.a); !result) {
        return result;
    }
    if (auto result = sync_client(scenario.b); !result) {
        return result;
    }
    if (auto result = sync_client(scenario.a); !result) {
        return result;
    }
    for (const auto* client : {&scenario.a, &scenario.b}) {
        if (auto valid = expect_file(*client, "conflict-file.txt", "A-V2");
            !valid) {
            return valid;
        }
        if (auto valid = expect_file(*client,
                                     "conflict-file.txt.kasumiconflict_local",
                                     "B-V2");
            !valid) {
            return valid;
        }
        if (auto absent = expect_absent(
                *client, "conflict-file.txt.kasumiconflict_remote");
            !absent) {
            return absent;
        }
    }
    return expect_converged(scenario, "two-client-conflict");
}

} // namespace kasumi::test::scenarios
