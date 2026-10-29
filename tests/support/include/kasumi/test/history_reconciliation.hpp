#ifndef KASUMI_TEST_HISTORY_RECONCILIATION_HPP
#define KASUMI_TEST_HISTORY_RECONCILIATION_HPP

#include "application/execute.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/history.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/provider_scenarios.hpp"
#include "platform/path.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <array>
#include <functional>
#include <map>
#include <set>
#include <stdexcept>

namespace kasumi::test::scenarios {

struct ReconciliationEvidence {
    std::vector<history::LoadedCommit> crossing_graph;
    std::vector<std::string> bases;
    std::vector<std::string> crossing_heads;
    Snapshot final_tree;
    std::size_t sync_calls = 0;
    std::size_t no_op_calls = 0;
    bool topology_confirmed = false;
    bool fsck_pass = false;
    bool converged = false;
};

// Temporarily withhold only newly published HEAD markers to make both writers
// observe the same frontier. All commits and contents still come from real
// Sync.
inline void reconcile_offline_criss_cross(
    const std::string& locator,
    const std::filesystem::path& scratch,
    const std::array<SyncScenarioClient, 3>& clients,
    const std::array<std::uint8_t, crypto::KEY_SIZE>& key,
    std::uint32_t seed,
    const std::function<void()>& verify_ownership,
    ReconciliationEvidence& evidence) {
    const auto require = [](bool condition, const std::string& detail) {
        if (!condition)
            throw std::runtime_error(detail);
    };
    std::filesystem::create_directories(scratch);
    auto opened = transport::open_transport(locator);
    if (!opened)
        throw std::runtime_error(opened.error().message);
    auto& storage = *opened;
    const auto layout = application::history_storage::derive_remote_layout(key);
    std::size_t observations = 0;
    const auto observe = [&] {
        const auto root =
            scratch / ("observe-" + std::to_string(observations++));
        std::filesystem::create_directories(root);
        auto view = application::observation::history::observe(
            storage, key, root, false);
        if (!view)
            throw std::runtime_error(view.error().detail);
        return std::move(*view);
    };
    const auto identifiers = [&] {
        auto listed = transport::list(storage);
        if (!listed)
            throw std::runtime_error(listed.error().message);
        std::ranges::sort(*listed);
        return std::move(*listed);
    };
    const auto sync = [&](const SyncScenarioClient& client) {
        ++evidence.sync_calls;
        auto result = application::execute(
            {application::Request{application::Operation::Sync, client.profile},
             application::Credentials{application::NoCredentials{}},
             client.environment});
        if (!result)
            throw std::runtime_error(client.profile + ": " +
                                     result.error().detail);
        const auto* completed =
            std::get_if<application::SyncCompleted>(&result->data);
        require(completed && !completed->partial && completed->pending == 0,
                "Sync incomplete");
        return *completed;
    };
    const auto put_local = [&](std::size_t client,
                               const std::string& path,
                               const std::string& value) {
        write_text(clients[client].local_root / path, value);
    };
    const auto value = [&](std::string_view name) {
        return std::string{name} + ";seed=" + std::to_string(seed);
    };

    put_local(0, "shared.txt", value("base"));
    for (const auto& client : clients)
        sync(client);
    const auto bootstrap = observe();
    require(bootstrap.logical_heads.size() == 1,
            "bootstrap must have one head");
    put_local(0, "offline.txt", value("offline"));

    for (int wave = 1; wave <= 2; ++wave) {
        put_local(1,
                  "a" + std::to_string(wave) + ".txt",
                  value("A" + std::to_string(wave)));
        put_local(2,
                  "b" + std::to_string(wave) + ".txt",
                  value("B" + std::to_string(wave)));
        if (wave == 1) {
            put_local(1, "shared.txt", value("left"));
            put_local(2, "shared.txt", value("right"));
        }
        const auto before = identifiers();
        std::vector<std::pair<std::string, std::filesystem::path>> frontier;
        for (const auto& id : before) {
            if (!application::history_storage::parse_marker_object(layout, id))
                continue;
            const auto copy = scratch / ("frontier-" + std::to_string(wave) +
                                         "-" + std::to_string(frontier.size()));
            auto saved = transport::get(storage, id, copy);
            if (!saved)
                throw std::runtime_error(saved.error().message);
            frontier.emplace_back(id, copy);
        }
        require(sync(clients[1]).published, "first writer did not publish");
        const auto after = identifiers();
        std::vector<std::string> added;
        for (const auto& id : after) {
            if (!std::ranges::binary_search(before, id) &&
                application::history_storage::parse_marker_object(layout, id)) {
                added.push_back(id);
            }
        }
        require(added.size() == 1, "expected one newly published marker");
        const auto backup = scratch / ("withheld-" + std::to_string(wave));
        auto saved = transport::get(storage, added.front(), backup);
        if (!saved)
            throw std::runtime_error(saved.error().message);
        verify_ownership();
        auto hidden = transport::remove(storage, added.front());
        if (!hidden)
            throw std::runtime_error(hidden.error().message);
        const auto absent = transport::presence(storage, added.front());
        require(absent && *absent == transport::Presence::Absent,
                "marker not withheld");
        // Sync prunes parent markers; expose the original frontier to writer B.
        for (const auto& [id, copy] : frontier) {
            auto restored_parent = transport::put(storage, copy, id);
            if (!restored_parent)
                throw std::runtime_error(restored_parent.error().message);
        }
        require(sync(clients[2]).published, "second writer did not publish");
        auto restored = transport::put(storage, backup, added.front());
        if (!restored)
            throw std::runtime_error(restored.error().message);
        const auto restored_copy =
            scratch / ("restored-" + std::to_string(wave));
        auto readback = transport::get(storage, added.front(), restored_copy);
        if (!readback)
            throw std::runtime_error(readback.error().message);
        require(read_binary(backup) == read_binary(restored_copy),
                "marker restoration mismatch");
        const auto view = observe();
        require(view.logical_heads.size() == 2,
                "wave must leave two logical heads");
        if (wave == 1) {
            evidence.bases = view.logical_heads;
        } else {
            evidence.crossing_graph = view.reachable_commits;
            evidence.crossing_heads = view.logical_heads;
            for (const auto& head : evidence.crossing_heads) {
                const auto found = std::ranges::find(
                    view.reachable_commits, head, &history::LoadedCommit::id);
                require(found != view.reachable_commits.end(),
                        "missing crossing head");
                require(found->commit.parents == evidence.bases,
                        "crossing head has wrong parents");
            }
            evidence.topology_confirmed = true;
        }
    }

    require(sync(clients[0]).published,
            "offline rejoin did not publish reconciliation");
    const auto joined = observe();
    require(joined.logical_heads.size() == 1,
            "rejoin must leave one logical head");
    const auto merge = std::ranges::find(joined.reachable_commits,
                                         joined.logical_heads.front(),
                                         &history::LoadedCommit::id);
    require(merge != joined.reachable_commits.end() &&
                merge->commit.parents == evidence.crossing_heads,
            "rejoin must publish the real crossing heads as parents");
    for (const auto& client : clients)
        sync(client);
    const auto final = observe();
    require(final.logical_heads.size() == 1,
            "final history must have one logical head");
    evidence.final_tree = final.effective_tree;
    const auto final_graph = history::resolve_authenticated(
        final.reachable_commits, final.marked_heads);
    require(final_graph.has_value(), "final DAG validation failed");

    const std::map<std::string, std::string> named{
        {"a1.txt", value("A1")},
        {"a2.txt", value("A2")},
        {"b1.txt", value("B1")},
        {"b2.txt", value("B2")},
        {"offline.txt", value("offline")}};
    std::multiset<std::string> expected;
    for (const auto& [path, content] : named) {
        static_cast<void>(path);
        expected.insert(content);
    }
    expected.insert(value("left"));
    expected.insert(value("right"));
    for (const auto& client : clients) {
        std::multiset<std::string> actual;
        for (const auto& entry :
             std::filesystem::recursive_directory_iterator(client.local_root)) {
            if (entry.is_regular_file())
                actual.insert(read_text(entry.path()));
        }
        require(actual == expected,
                "client lost or duplicated confirmed content");
        for (const auto& [path, content] : named) {
            require(read_text(client.local_root / path) == content,
                    "independent path changed");
        }
        auto runtime = runtime::resolve(client.environment.app_data_dir,
                                        client.profile,
                                        runtime::AccessMode::ReadOnly);
        if (!runtime)
            throw std::runtime_error(runtime.error().detail);
        auto accepted = state_storage::load_state(runtime->database_path);
        require(accepted && accepted->has_value(),
                "missing accepted client state");
        require((**accepted).commit_id == final.logical_heads.front() &&
                    (**accepted).tree == final.effective_tree,
                "client did not accept final head and snapshot");
    }
    require(std::ranges::count_if(final.effective_tree.rows,
                                  [](const auto& row) {
                                      return row.path.find(
                                                 ".kasumiconflict_") !=
                                             std::string::npos;
                                  }) == 1,
            "expected exactly one preserved file conflict");
    evidence.converged = true;

    const auto& client = clients[0];
    auto fsck = application::execute(
        {application::Request{application::Operation::Fsck, client.profile},
         application::Credentials{application::NoCredentials{}},
         client.environment});
    if (!fsck)
        throw std::runtime_error(fsck.error().detail);
    evidence.fsck_pass = true;
    const auto before_no_op = identifiers();
    for (const auto& current : clients) {
        require(!sync(current).published,
                "no-op Sync published another commit");
        ++evidence.no_op_calls;
    }
    require(identifiers() == before_no_op, "no-op Sync changed remote objects");
}

} // namespace kasumi::test::scenarios

#endif
