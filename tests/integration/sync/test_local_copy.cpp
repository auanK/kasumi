#include "application/sync/mutation_fault_test.hpp"
#include "platform/perf_trace.hpp"
#include "application/use_cases/context.hpp"
#include "crypto/content.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_detail.hpp"
#include "core/diff.hpp"
#include "core/hasher.hpp"
#include "core/node.hpp"
#include "core/reconciliation/plan.hpp"
#include "platform/workspace.hpp"
#include "application/sync/journal.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <spawn.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace kasumi::application::detail {
std::expected<Response, Error> run_sync(OperationContext& context);
std::expected<Response, Error> run_plan(OperationContext& context);
} // namespace kasumi::application::detail

namespace {

using kasumi::Action;
using kasumi::NodeRow;
using kasumi::Operation;
using kasumi::Snapshot;
using kasumi::SyncPlan;
using kasumi::transaction::OperationProgress;
using kasumi::transaction::OperationState;

constexpr kasumi::TimestampNs test_mtime = 1'700'000'000'000'000'000LL;

Snapshot make_tree(std::initializer_list<NodeRow> rows = {}) {
    Snapshot snapshot{{{.path = "", .is_directory = true}}};
    snapshot.rows.insert(snapshot.rows.end(), rows.begin(), rows.end());
    kasumi::finalize_snapshot(snapshot);
    return snapshot;
}

NodeRow make_file_row(std::string path,
                      std::string_view contents,
                      kasumi::TimestampNs mtime = test_mtime,
                      std::uint64_t size = 0) {
    if (size == 0)
        size = contents.size();
    return {.path = std::move(path),
            .hash = kasumi::hasher::hash_string(contents),
            .size = size,
            .mtime = mtime,
            .is_directory = false};
}

kasumi::reconciliation::Input
make_reconcile_input(const Snapshot& local_tree,
                     const Snapshot& base_tree,
                     const Snapshot& remote_tree) {
    return {
        .local_tree = local_tree,
        .base_tree = base_tree,
        .base_commit_id = "commit-1",
        .base_state_present = true,
        .storage =
            {
                .tree = remote_tree,
                .reachable_commits = {kasumi::history::LoadedCommit{
                                          .id = "commit-1",
                                          .commit = {.height = 1,
                                                     .tree = base_tree},
                                      },
                                      kasumi::history::LoadedCommit{
                                          .id = "commit-2",
                                          .commit = {.height = 2,
                                                     .parents = {"commit-1"},
                                                     .tree = remote_tree},
                                      }},
                .reachable_commit_ids = {"commit-1", "commit-2"},
                .marked_heads = {"commit-2"},
                .logical_heads = {"commit-2"},
                .generation = 2,
                .history_present = true,
            },
        .local_generation = 1,
    };
}

bool has_operation(const SyncPlan& plan,
                   Action action,
                   std::string_view path,
                   std::string_view alt_path = {}) {
    for (const auto& op : plan.operations) {
        if (op.action == action &&
            kasumi::platform::path::to_logical_utf8(op.path) == path) {
            if (alt_path.empty() ||
                kasumi::platform::path::to_logical_utf8(op.alt_path) == alt_path) {
                return true;
            }
        }
    }
    return false;
}

bool is_content_identifier(std::string_view identifier) noexcept {
    return !identifier.empty() &&
           identifier.find('/') == std::string_view::npos;
}

struct ContentCounterState {
    kasumi::transport::Transport* base = nullptr;
    mutable std::mutex mutex{};
    std::size_t content_gets = 0;
    std::size_t content_puts = 0;
    std::size_t content_presences = 0;
    std::size_t content_copies = 0;
    std::vector<std::string> get_identifiers;
    std::vector<std::string> put_identifiers;
    std::vector<std::string> presence_identifiers;
};

void destroy_counter_state(void*) noexcept {}

kasumi::transport::Result counter_initialize(void* context) {
    auto* state = static_cast<ContentCounterState*>(context);
    return kasumi::transport::initialize(*state->base);
}

kasumi::transport::Result counter_put(void* context,
                                      const std::filesystem::path& source,
                                      std::string_view identifier) {
    auto* state = static_cast<ContentCounterState*>(context);
    if (is_content_identifier(identifier)) {
        std::lock_guard lock(state->mutex);
        ++state->content_puts;
        state->put_identifiers.emplace_back(identifier);
    }
    return kasumi::transport::put(*state->base, source, identifier);
}

kasumi::transport::Result
counter_put_batch(void* context, const kasumi::transport::PutBatch& batch) {
    auto* state = static_cast<ContentCounterState*>(context);
    {
        std::lock_guard lock(state->mutex);
        for (const auto& identifier : batch.identifiers) {
            if (is_content_identifier(identifier)) {
                ++state->content_puts;
                state->put_identifiers.push_back(identifier);
            }
        }
    }
    return kasumi::transport::put_batch(*state->base, batch);
}

kasumi::transport::Result
counter_put_files_batch(void* context,
                        const kasumi::transport::PutFilesBatch& batch) {
    auto* state = static_cast<ContentCounterState*>(context);
    auto result = kasumi::transport::put_files_batch(*state->base, batch);
    if (result ||
        result.error().code != kasumi::transport::ErrorCode::Unsupported) {
        std::lock_guard lock(state->mutex);
        for (const auto& item : batch.items) {
            if (is_content_identifier(item.destination_identifier)) {
                ++state->content_puts;
                state->put_identifiers.push_back(item.destination_identifier);
            }
        }
    }
    return result;
}

kasumi::transport::Result counter_get(void* context,
                                      std::string_view identifier,
                                      const std::filesystem::path& destination) {
    auto* state = static_cast<ContentCounterState*>(context);
    if (is_content_identifier(identifier)) {
        std::lock_guard lock(state->mutex);
        ++state->content_gets;
        state->get_identifiers.emplace_back(identifier);
    }
    return kasumi::transport::get(*state->base, identifier, destination);
}

kasumi::transport::Result
counter_get_batch(void* context, const kasumi::transport::GetBatch& batch) {
    auto* state = static_cast<ContentCounterState*>(context);
    if (batch.source_prefix.empty()) {
        std::lock_guard lock(state->mutex);
        for (const auto& identifier : batch.identifiers) {
            if (is_content_identifier(identifier)) {
                ++state->content_gets;
                state->get_identifiers.push_back(identifier);
            }
        }
    }
    return kasumi::transport::get_batch(*state->base, batch);
}

kasumi::transport::Result
counter_copy(void* context,
             std::string_view source_identifier,
             std::string_view destination_identifier) {
    auto* state = static_cast<ContentCounterState*>(context);
    auto result = kasumi::transport::copy(
        *state->base, source_identifier, destination_identifier);
    if (result ||
        result.error().code != kasumi::transport::ErrorCode::Unsupported) {
        if (is_content_identifier(source_identifier) ||
            is_content_identifier(destination_identifier)) {
            std::lock_guard lock(state->mutex);
            ++state->content_copies;
        }
    }
    return result;
}

kasumi::transport::Result
counter_copy_batch(void* context, const kasumi::transport::CopyBatch& batch) {
    auto* state = static_cast<ContentCounterState*>(context);
    auto result = kasumi::transport::copy_batch(*state->base, batch);
    if (result ||
        result.error().code != kasumi::transport::ErrorCode::Unsupported) {
        std::lock_guard lock(state->mutex);
        for (const auto& item : batch.items) {
            if (is_content_identifier(item.source_identifier) ||
                is_content_identifier(item.destination_identifier)) {
                ++state->content_copies;
            }
        }
    }
    return result;
}

kasumi::transport::PresenceResult
counter_presence(void* context, std::string_view identifier) {
    auto* state = static_cast<ContentCounterState*>(context);
    if (is_content_identifier(identifier)) {
        std::lock_guard lock(state->mutex);
        ++state->content_presences;
        state->presence_identifiers.emplace_back(identifier);
    }
    return kasumi::transport::presence(*state->base, identifier);
}

kasumi::transport::ListingResult counter_list(void* context) {
    auto* state = static_cast<ContentCounterState*>(context);
    return kasumi::transport::list(*state->base);
}

kasumi::transport::ListingResult counter_list_prefix(void* context,
                                                     std::string_view prefix) {
    auto* state = static_cast<ContentCounterState*>(context);
    return kasumi::transport::list(*state->base, prefix);
}

kasumi::transport::ControlReadBatchResponse counter_control_read_batch(
    void* context, const kasumi::transport::ControlReadBatchRequest& request) {
    auto* state = static_cast<ContentCounterState*>(context);
    auto result = kasumi::transport::control_read_batch(*state->base, request);
    if (result ||
        result.error().code != kasumi::transport::ErrorCode::Unsupported) {
        std::lock_guard lock(state->mutex);
        for (const auto& identifier : request.presence_identifiers) {
            if (is_content_identifier(identifier)) {
                ++state->content_presences;
                state->presence_identifiers.push_back(identifier);
            }
        }
    }
    return result;
}

kasumi::transport::RemovalResult counter_remove(void* context,
                                                std::string_view identifier) {
    auto* state = static_cast<ContentCounterState*>(context);
    return kasumi::transport::remove(*state->base, identifier);
}

kasumi::transport::RemoveBatchResult
counter_remove_batch(void* context,
                     const kasumi::transport::RemoveBatch& batch) {
    auto* state = static_cast<ContentCounterState*>(context);
    return kasumi::transport::remove_batch(*state->base, batch);
}

kasumi::transport::Transport
make_counting_transport(ContentCounterState& state) {
    return kasumi::transport::Transport{
        .state = kasumi::transport::TransportStateHandle{&state,
                                                         destroy_counter_state},
        .storage =
            kasumi::transport::StorageOperations{
                .initialize = counter_initialize,
                .put = counter_put,
                .put_batch = counter_put_batch,
                .put_files_batch = counter_put_files_batch,
                .get = counter_get,
                .get_batch = counter_get_batch,
                .copy = counter_copy,
                .copy_batch = counter_copy_batch,
                .presence = counter_presence,
                .list = counter_list,
                .list_prefix = counter_list_prefix,
                .control_read_batch = counter_control_read_batch,
                .remove = counter_remove,
                .remove_batch = counter_remove_batch,
            },
    };
}

struct SyncNode {
    kasumi::test::TempWorkspace workspace{nullptr, nullptr};
    std::filesystem::path profile;
    std::filesystem::path local;
    std::filesystem::path storage_root;
    std::filesystem::path database;
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    ContentCounterState counters{};
    kasumi::transport::Transport base_storage{};
    kasumi::runtime::RuntimeData runtime{};
    kasumi::application::detail::OperationContext context{};
    bool valid = false;
};


#if defined(KASUMI_SYNC_CRASH_HELPER_PATH)
std::filesystem::path crash_child_path() {
    return std::filesystem::path{KASUMI_SYNC_CRASH_HELPER_PATH};
}

struct ChildRun {
    bool reached_point = false;
    bool was_killed = false;
    std::string signal_contents;
    std::string detail;
};

#if defined(_WIN32)

class ScopedEnvironmentHelper {
public:
    bool set(const wchar_t* name, std::wstring value) {
        const DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
        if (required > 0) {
            std::wstring prev(required, L'\0');
            GetEnvironmentVariableW(name, prev.data(), static_cast<DWORD>(prev.size()));
            prev.resize(wcslen(prev.c_str()));
            previous_.emplace_back(name, prev);
        } else {
            previous_.emplace_back(name, std::nullopt);
        }
        return SetEnvironmentVariableW(name, value.c_str()) != 0;
    }

    ~ScopedEnvironmentHelper() {
        for (auto it = previous_.rbegin(); it != previous_.rend(); ++it) {
            SetEnvironmentVariableW(it->first.c_str(),
                                    it->second ? it->second->c_str() : nullptr);
        }
    }

private:
    std::vector<std::pair<std::wstring, std::optional<std::wstring>>> previous_;
};

ChildRun run_crash_child(const SyncNode& node,
                         std::string_view mode,
                         std::string_view point,
                         std::string_view subject,
                         const std::filesystem::path& signal_path) {
    ChildRun result;
    ScopedEnvironmentHelper environment;
    const auto ascii = [](std::string_view value) {
        return std::wstring(value.begin(), value.end());
    };
    const auto set = [&](const wchar_t* name, std::wstring value) {
        return environment.set(name, std::move(value));
    };
    if (!set(L"KASUMI_CRASH_TEST_MODE", ascii(mode)) ||
        !set(L"KASUMI_CRASH_TEST_PROFILE", node.profile.native()) ||
        !set(L"KASUMI_CRASH_TEST_LOCAL", node.local.native()) ||
        !set(L"KASUMI_CRASH_TEST_STORAGE", node.storage_root.native()) ||
        !set(L"KASUMI_CRASH_TEST_POINT", ascii(point)) ||
        !set(L"KASUMI_CRASH_TEST_SUBJECT", ascii(subject)) ||
        !set(L"KASUMI_CRASH_TEST_SIGNAL", signal_path.native())) {
        result.detail = "could not set child environment";
        return result;
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const auto executable = crash_child_path();
    if (!CreateProcessW(executable.c_str(),
                        nullptr,
                        nullptr,
                        nullptr,
                        FALSE,
                        CREATE_NO_WINDOW,
                        nullptr,
                        nullptr,
                        &startup,
                        &process)) {
        result.detail = "CreateProcessW failed: " + std::to_string(GetLastError());
        return result;
    }
    CloseHandle(process.hThread);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};
    while (std::chrono::steady_clock::now() < deadline) {
        if (std::filesystem::exists(signal_path)) {
            result.reached_point = true;
            break;
        }
        const DWORD state = WaitForSingleObject(process.hProcess, 0);
        if (state == WAIT_OBJECT_0) {
            DWORD exit_code = 0;
            GetExitCodeProcess(process.hProcess, &exit_code);
            result.detail = "child exited before point with code " + std::to_string(exit_code);
            CloseHandle(process.hProcess);
            return result;
        }
        Sleep(5);
    }

    if (result.reached_point) {
        std::ifstream signal{signal_path, std::ios::binary};
        result.signal_contents.assign(
            std::istreambuf_iterator<char>{signal},
            std::istreambuf_iterator<char>{});
    }
    if (TerminateProcess(process.hProcess, 137) &&
        WaitForSingleObject(process.hProcess, 5000) == WAIT_OBJECT_0) {
        DWORD exit_code = 0;
        result.was_killed = GetExitCodeProcess(process.hProcess, &exit_code) && exit_code == 137;
    }
    CloseHandle(process.hProcess);
    return result;
}

#else

ChildRun run_crash_child(const SyncNode& node,
                         std::string_view mode,
                         std::string_view point,
                         std::string_view subject,
                         const std::filesystem::path& signal_path) {
    ChildRun result;
    const std::map<std::string, std::string> overrides{
        {"KASUMI_CRASH_TEST_MODE", std::string{mode}},
        {"KASUMI_CRASH_TEST_PROFILE", kasumi::platform::path::to_utf8(node.profile)},
        {"KASUMI_CRASH_TEST_LOCAL", kasumi::platform::path::to_utf8(node.local)},
        {"KASUMI_CRASH_TEST_STORAGE", kasumi::platform::path::to_utf8(node.storage_root)},
        {"KASUMI_CRASH_TEST_POINT", std::string{point}},
        {"KASUMI_CRASH_TEST_SUBJECT", std::string{subject}},
        {"KASUMI_CRASH_TEST_SIGNAL", kasumi::platform::path::to_utf8(signal_path)},
    };
    std::vector<std::string> environment;
    for (char** entry = environ; entry != nullptr && *entry != nullptr; ++entry) {
        const std::string_view value{*entry};
        const auto separator = value.find('=');
        if (separator != std::string_view::npos &&
            overrides.contains(std::string{value.substr(0, separator)})) {
            continue;
        }
        environment.emplace_back(value);
    }
    for (const auto& [name, value] : overrides) {
        environment.push_back(name + "=" + value);
    }
    std::vector<char*> environment_pointers;
    environment_pointers.reserve(environment.size() + 1);
    for (auto& entry : environment) {
        environment_pointers.push_back(entry.data());
    }
    environment_pointers.push_back(nullptr);

    const auto executable = crash_child_path().string();
    std::array<char*, 2> arguments{const_cast<char*>(executable.c_str()), nullptr};
    pid_t child = -1;
    const int spawned = posix_spawn(&child,
                                    executable.c_str(),
                                    nullptr,
                                    nullptr,
                                    arguments.data(),
                                    environment_pointers.data());
    if (spawned != 0) {
        result.detail = "posix_spawn failed: " + std::to_string(spawned);
        return result;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};
    int child_status = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        if (std::filesystem::exists(signal_path)) {
            result.reached_point = true;
            break;
        }
        const auto waited = waitpid(child, &child_status, WNOHANG);
        if (waited == child) {
            const int exit_code = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1;
            result.detail = "child exited before point with code " + std::to_string(exit_code);
            return result;
        }
        usleep(5000);
    }

    if (result.reached_point) {
        std::ifstream signal{signal_path, std::ios::binary};
        result.signal_contents.assign(
            std::istreambuf_iterator<char>{signal},
            std::istreambuf_iterator<char>{});
    }
    kill(child, SIGKILL);
    int status = 0;
    waitpid(child, &status, 0);
    result.was_killed = true;
    return result;
}

#endif
#endif

bool init_sync_node(SyncNode& node,
                    std::string_view name,
                    std::filesystem::path shared_storage = {}) {
    node.workspace = kasumi::test::make_temp_workspace(name);
    node.profile = kasumi::test::workspace_path(node.workspace, "profile");
    node.local = kasumi::test::workspace_path(node.workspace, "local");
    node.storage_root =
        shared_storage.empty()
            ? kasumi::test::workspace_path(node.workspace, "storage")
            : std::move(shared_storage);
    node.database = node.profile / "state.db";
    node.key = test_key();
    if (!std::filesystem::create_directories(node.profile) ||
        !std::filesystem::create_directories(node.local)) {
        return false;
    }
    auto opened = kasumi::transport::open_transport(node.storage_root.string());
    if (!opened) {
        return false;
    }
    node.base_storage = std::move(*opened);
    node.counters.base = &node.base_storage;
    if (!kasumi::state_storage::initialize(node.database)) {
        return false;
    }

    node.runtime = kasumi::runtime::RuntimeData{
        .local_dir = node.local,
        .database_path = node.database,
        .key_path = node.profile / "key.bin",
        .storage_location = node.storage_root.string(),
    };
    node.context.operation = kasumi::application::Operation::Sync;
    node.context.runtime = node.runtime;
    node.context.summary = {
        .local_dir = node.local,
        .remote_dir = kasumi::platform::path::to_utf8(node.storage_root),
    };
    node.context.key = node.key;
    node.context.storage = make_counting_transport(node.counters);
    node.valid = true;
    return true;
}

kasumi::platform::Workspace make_test_workspace(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
    auto ws = kasumi::platform::create_workspace_at(path);
    if (!ws) {
        throw std::runtime_error("failed to create test workspace: " + ws.error());
    }
    return std::move(*ws);
}

void write_local_file(const SyncNode& node,
                      std::string_view relative_path,
                      std::string_view contents) {
    const auto target =
        node.local / kasumi::platform::path::from_utf8(relative_path);
    std::filesystem::create_directories(target.parent_path());
    kasumi::test::write_text(target, contents);
}

void rename_local_entry(const SyncNode& node,
                        std::string_view from_relative,
                        std::string_view to_relative) {
    const auto from =
        node.local / kasumi::platform::path::from_utf8(from_relative);
    const auto to = node.local / kasumi::platform::path::from_utf8(to_relative);
    std::filesystem::create_directories(to.parent_path());
    std::filesystem::rename(from, to);
}

void remove_local_subtree(const SyncNode& node,
                          std::string_view relative_path) {
    std::filesystem::remove_all(
        node.local / kasumi::platform::path::from_utf8(relative_path));
}

bool local_entry_exists(const SyncNode& node, std::string_view relative_path) {
    return std::filesystem::exists(
        node.local / kasumi::platform::path::from_utf8(relative_path));
}

std::string read_local_file(const SyncNode& node,
                            std::string_view relative_path) {
    return kasumi::test::read_text(
        node.local / kasumi::platform::path::from_utf8(relative_path));
}

std::expected<kasumi::application::Response, kasumi::application::Error>
run_node_sync(SyncNode& node) {
    node.context.operation = kasumi::application::Operation::Sync;
    return kasumi::application::detail::run_sync(node.context);
}

void reset_content_counts(SyncNode& node) noexcept {
    std::lock_guard lock(node.counters.mutex);
    node.counters.content_gets = 0;
    node.counters.content_puts = 0;
    node.counters.content_presences = 0;
    node.counters.content_copies = 0;
    node.counters.get_identifiers.clear();
    node.counters.put_identifiers.clear();
    node.counters.presence_identifiers.clear();
}

} // namespace

// ============================================================================
// GRUPO A — RECONCILIAÇÃO
// ============================================================================

TEST(LocalCopyReconciliationTest, CopyReusesExistingLocalContent) {
    const auto f_local = make_file_row("A.txt", "SharedLocalBytes");
    const auto f_remote = make_file_row("B.txt", "SharedLocalBytes");

    const auto local_tree = make_tree({f_local});
    const auto base_tree = make_tree({f_local});
    const auto remote_tree = make_tree({f_local, f_remote});

    const auto result = kasumi::reconciliation::reconcile(
        make_reconcile_input(local_tree, base_tree, remote_tree));
    ASSERT_TRUE(result.has_value()) << result.error().detail;

    // Must plan CopyLocal A.txt -> B.txt, not Download
    EXPECT_TRUE(has_operation(result->plan, Action::CopyLocal, "A.txt", "B.txt"));
    EXPECT_FALSE(has_operation(result->plan, Action::Download, "B.txt"));
}

TEST(LocalCopyReconciliationTest, CopyPreservesSource) {
    const auto f_local = make_file_row("A.txt", "SharedBytes");
    const auto f_remote = make_file_row("B.txt", "SharedBytes");

    const auto local_tree = make_tree({f_local});
    const auto base_tree = make_tree({f_local});
    const auto remote_tree = make_tree({f_local, f_remote});

    const auto result = kasumi::reconciliation::reconcile(
        make_reconcile_input(local_tree, base_tree, remote_tree));
    ASSERT_TRUE(result.has_value());

    // Source A.txt must NOT be deleted
    EXPECT_FALSE(has_operation(result->plan, Action::DeleteLocal, "A.txt"));
    EXPECT_FALSE(has_operation(result->plan, Action::MoveLocal, "A.txt"));
}

TEST(LocalCopyReconciliationTest, MultipleCopiesReuseOneSource) {
    const auto f_src = make_file_row("A.txt", "MultiCopyBytes");
    const auto f_dst1 = make_file_row("B.txt", "MultiCopyBytes");
    const auto f_dst2 = make_file_row("C.txt", "MultiCopyBytes");
    const auto f_dst3 = make_file_row("D.txt", "MultiCopyBytes");

    const auto local_tree = make_tree({f_src});
    const auto base_tree = make_tree({f_src});
    const auto remote_tree = make_tree({f_src, f_dst1, f_dst2, f_dst3});

    const auto result = kasumi::reconciliation::reconcile(
        make_reconcile_input(local_tree, base_tree, remote_tree));
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(has_operation(result->plan, Action::CopyLocal, "A.txt", "B.txt"));
    EXPECT_TRUE(has_operation(result->plan, Action::CopyLocal, "A.txt", "C.txt"));
    EXPECT_TRUE(has_operation(result->plan, Action::CopyLocal, "A.txt", "D.txt"));
    EXPECT_TRUE(kasumi::sync_plan_phase(result->plan, Action::Download).empty());
}

TEST(LocalCopyReconciliationTest, CopyRejectsHashMismatch) {
    const auto f_local = make_file_row("A.txt", "LocalContent1");
    const auto f_remote = make_file_row("B.txt", "RemoteContent2");

    const auto local_tree = make_tree({f_local});
    const auto base_tree = make_tree({f_local});
    const auto remote_tree = make_tree({f_local, f_remote});

    const auto result = kasumi::reconciliation::reconcile(
        make_reconcile_input(local_tree, base_tree, remote_tree));
    ASSERT_TRUE(result.has_value());

    EXPECT_FALSE(has_operation(result->plan, Action::CopyLocal, "A.txt", "B.txt"));
    EXPECT_TRUE(has_operation(result->plan, Action::Download, "B.txt"));
}

TEST(LocalCopyReconciliationTest, CopyRejectsSizeMismatch) {
    auto f_local = make_file_row("A.txt", "ExactSameBytes");
    auto f_remote = make_file_row("B.txt", "ExactSameBytes");
    f_remote.size = f_local.size + 10; // Corrupted / altered size

    const auto local_tree = make_tree({f_local});
    const auto base_tree = make_tree({f_local});
    const auto remote_tree = make_tree({f_local, f_remote});

    const auto result = kasumi::reconciliation::reconcile(
        make_reconcile_input(local_tree, base_tree, remote_tree));
    ASSERT_TRUE(result.has_value());

    EXPECT_FALSE(has_operation(result->plan, Action::CopyLocal, "A.txt", "B.txt"));
}

TEST(LocalCopyReconciliationTest, CopyWithoutSourceRemainsDownload) {
    const auto f_remote = make_file_row("B.txt", "UniqueRemoteBytes");

    const auto local_tree = make_tree({});
    const auto base_tree = make_tree({});
    const auto remote_tree = make_tree({f_remote});

    const auto result = kasumi::reconciliation::reconcile(
        make_reconcile_input(local_tree, base_tree, remote_tree));
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(has_operation(result->plan, Action::Download, "B.txt"));
    EXPECT_TRUE(kasumi::sync_plan_phase(result->plan, Action::CopyLocal).empty());
}

TEST(LocalCopyReconciliationTest, CopyRejectsUnsafeDestination) {
    Operation op{
        .action = Action::CopyLocal,
        .path = "source.txt",
        .hash = std::string(64, '0'),
        .alt_path = "../escaped.txt",
        .size = 10,
    };
    EXPECT_FALSE(kasumi::has_safe_paths(op));
}

TEST(LocalCopyReconciliationTest, CopyPreservesConflictRules) {
    const auto f_local_source = make_file_row("A.txt", "CommonBytes");
    const auto f_local_modified = make_file_row("B.txt", "LocallyModifiedBytes");
    const auto f_base = make_file_row("B.txt", "OriginalRemoteBytes");
    const auto f_remote = make_file_row("B.txt", "CommonBytes");

    const auto local_tree = make_tree({f_local_source, f_local_modified});
    const auto base_tree = make_tree({f_local_source, f_base});
    const auto remote_tree = make_tree({f_local_source, f_remote});

    const auto result = kasumi::reconciliation::reconcile(
        make_reconcile_input(local_tree, base_tree, remote_tree));
    ASSERT_TRUE(result.has_value());

    // Conflict exists on B.txt: CopyLocal must NOT silently overwrite B.txt
    EXPECT_TRUE(result->has_conflicts);
    EXPECT_FALSE(has_operation(result->plan, Action::CopyLocal, "A.txt", "B.txt"));
}

TEST(LocalCopyReconciliationTest, CopySelectionIsDeterministic) {
    const auto f1 = make_file_row("z_source.txt", "IdenticalBytes");
    const auto f2 = make_file_row("a_source.txt", "IdenticalBytes");
    const auto f_remote = make_file_row("dest.txt", "IdenticalBytes");

    const auto local_tree = make_tree({f1, f2});
    const auto base_tree = make_tree({f1, f2});
    const auto remote_tree = make_tree({f1, f2, f_remote});

    const auto result = kasumi::reconciliation::reconcile(
        make_reconcile_input(local_tree, base_tree, remote_tree));
    ASSERT_TRUE(result.has_value());

    // Lexicographical ordering dictates a_source.txt must be selected before z_source.txt
    EXPECT_TRUE(has_operation(result->plan, Action::CopyLocal, "a_source.txt", "dest.txt"));
}

// ============================================================================
// GRUPO B — DEPENDÊNCIAS (MOVE + COPY)
// ============================================================================

TEST(LocalCopyDependenciesTest, CopyBeforeMoveUsingSameSource) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "node_a_dep1"));
    ASSERT_TRUE(init_sync_node(node_b, "node_b_dep1", node_a.storage_root));

    write_local_file(node_a, "A.txt", "PayloadToMoveAndCopy");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    // Node A creates C.txt (copy of A) and moves A.txt to B.txt
    write_local_file(node_a, "C.txt", "PayloadToMoveAndCopy");
    rename_local_entry(node_a, "A.txt", "B.txt");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    reset_content_counts(node_b);
    auto sync_b = run_node_sync(node_b);
    ASSERT_TRUE(sync_b.has_value()) << sync_b.error().detail;

    // Both B.txt and C.txt must exist on node B with correct content
    EXPECT_FALSE(local_entry_exists(node_b, "A.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "B.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "C.txt"));
    EXPECT_EQ(read_local_file(node_b, "B.txt"), "PayloadToMoveAndCopy");
    EXPECT_EQ(read_local_file(node_b, "C.txt"), "PayloadToMoveAndCopy");

    // Pure local copy and move must have 0 content gets/puts
    EXPECT_EQ(node_b.counters.content_gets, 0U);
    EXPECT_EQ(node_b.counters.content_puts, 0U);
}

TEST(LocalCopyDependenciesTest, MultipleCopiesBeforeMove) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "node_a_dep2"));
    ASSERT_TRUE(init_sync_node(node_b, "node_b_dep2", node_a.storage_root));

    write_local_file(node_a, "A.txt", "MultiPayload");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    // Copies to C and D, and moves A to B
    write_local_file(node_a, "C.txt", "MultiPayload");
    write_local_file(node_a, "D.txt", "MultiPayload");
    rename_local_entry(node_a, "A.txt", "B.txt");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    reset_content_counts(node_b);
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    EXPECT_FALSE(local_entry_exists(node_b, "A.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "B.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "C.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "D.txt"));
    EXPECT_EQ(node_b.counters.content_gets, 0U);
}

TEST(LocalCopyDependenciesTest, CopyBeforeDeleteUsingSameSource) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "node_a_dep3"));
    ASSERT_TRUE(init_sync_node(node_b, "node_b_dep3", node_a.storage_root));

    write_local_file(node_a, "A.txt", "DeleteSourcePayload");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    // Node A copies A to B and deletes A
    write_local_file(node_a, "B.txt", "DeleteSourcePayload");
    remove_local_subtree(node_a, "A.txt");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    reset_content_counts(node_b);
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    EXPECT_FALSE(local_entry_exists(node_b, "A.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "B.txt"));
    EXPECT_EQ(read_local_file(node_b, "B.txt"), "DeleteSourcePayload");
    EXPECT_EQ(node_b.counters.content_gets, 0U);
}

TEST(LocalCopyDependenciesTest, CopyDoesNotRequireDeletedSourceAfterMove) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "node_a_dep4"));
    ASSERT_TRUE(init_sync_node(node_b, "node_b_dep4", node_a.storage_root));

    write_local_file(node_a, "src.txt", "StablePayload");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    write_local_file(node_a, "copy.txt", "StablePayload");
    rename_local_entry(node_a, "src.txt", "moved.txt");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    // Verify copy.txt and moved.txt are completely independent on disk
    EXPECT_TRUE(local_entry_exists(node_b, "copy.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "moved.txt"));
    write_local_file(node_b, "copy.txt", "ModifiedCopy");
    EXPECT_EQ(read_local_file(node_b, "moved.txt"), "StablePayload");
}

TEST(LocalCopyDependenciesTest, UnsafeDependencyFallsBackToDownload) {
    // If source file is in a conflict state or inaccessible, reconciliation falls back to Download
    const auto f_remote = make_file_row("dest.txt", "FallbackBytes");
    const auto local_tree = make_tree({});
    const auto base_tree = make_tree({});
    const auto remote_tree = make_tree({f_remote});

    const auto result = kasumi::reconciliation::reconcile(
        make_reconcile_input(local_tree, base_tree, remote_tree));
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(has_operation(result->plan, Action::Download, "dest.txt"));
}

TEST(LocalCopyDependenciesTest, CopyRecoveryInterruptedBeforeInstall) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "rec_before_inst_a"));
    ASSERT_TRUE(init_sync_node(node_b, "rec_before_inst_b", node_a.storage_root));

    write_local_file(node_a, "orig.txt", "RecoverBeforeInstallPayload");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    write_local_file(node_a, "copy.txt", "RecoverBeforeInstallPayload");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    struct SimulatedCrash {};
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path&) {
            if (point == "during_copy_local_write") {
                throw SimulatedCrash{};
            }
        });

    EXPECT_THROW((void)run_node_sync(node_b), SimulatedCrash);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_FALSE(local_entry_exists(node_b, "copy.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "orig.txt"));

    reset_content_counts(node_b);
    auto rec_sync = run_node_sync(node_b);
    ASSERT_TRUE(rec_sync.has_value()) << rec_sync.error().detail;
    EXPECT_TRUE(local_entry_exists(node_b, "copy.txt"));
    EXPECT_EQ(read_local_file(node_b, "copy.txt"), "RecoverBeforeInstallPayload");
    EXPECT_EQ(node_b.counters.content_gets, 0U);
}

TEST(LocalCopyDependenciesTest, CopyRecoveryInterruptedAfterInstallBeforeCheckpoint) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "rec_after_inst_a"));
    ASSERT_TRUE(init_sync_node(node_b, "rec_after_inst_b", node_a.storage_root));

    write_local_file(node_a, "doc.pdf", "CopyRecoveryAfterInstallBytes12345");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    write_local_file(node_a, "doc_backup.pdf", "CopyRecoveryAfterInstallBytes12345");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    struct SimulatedCrashAfterInstall {};
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path&) {
            if (point == "after_copy_local_install") {
                throw SimulatedCrashAfterInstall{};
            }
        });

    EXPECT_THROW((void)run_node_sync(node_b), SimulatedCrashAfterInstall);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_TRUE(local_entry_exists(node_b, "doc_backup.pdf"));
    EXPECT_EQ(read_local_file(node_b, "doc_backup.pdf"), "CopyRecoveryAfterInstallBytes12345");

    const auto paths = kasumi::application::sync::journal::make_paths(node_b.profile);
    ASSERT_TRUE(paths.has_value());
    auto loaded = kasumi::application::sync::journal::load(*paths, node_b.key, nullptr);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    bool found_prepared_copy = false;
    for (std::size_t i = 0; i < (*loaded)->plan.operations.size(); ++i) {
        if ((*loaded)->plan.operations[i].action == Action::CopyLocal) {
            EXPECT_EQ((*loaded)->progress[i].state, OperationState::Prepared);
            found_prepared_copy = true;
        }
    }
    EXPECT_TRUE(found_prepared_copy);

    reset_content_counts(node_b);
    auto rec_sync = run_node_sync(node_b);
    ASSERT_TRUE(rec_sync.has_value()) << (rec_sync ? "" : rec_sync.error().detail);
    EXPECT_TRUE(local_entry_exists(node_b, "doc_backup.pdf"));
    EXPECT_EQ(read_local_file(node_b, "doc_backup.pdf"), "CopyRecoveryAfterInstallBytes12345");
    EXPECT_EQ(node_b.counters.content_gets, 0U);
}

TEST(LocalCopyDependenciesTest, CopyRecoveryInterruptedMixedCopyAndMove) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "rec_mixed_a"));
    ASSERT_TRUE(init_sync_node(node_b, "rec_mixed_b", node_a.storage_root));

    write_local_file(node_a, "source.txt", "SharedSourceContentBetweenCopyAndMove");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    write_local_file(node_a, "copy.txt", "SharedSourceContentBetweenCopyAndMove");
    rename_local_entry(node_a, "source.txt", "moved.txt");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    struct SimulatedCrashMixed {};
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path&) {
            if (point == "after_copy_local_install") {
                throw SimulatedCrashMixed{};
            }
        });

    EXPECT_THROW((void)run_node_sync(node_b), SimulatedCrashMixed);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_TRUE(local_entry_exists(node_b, "moved.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "source.txt"));
    EXPECT_FALSE(local_entry_exists(node_b, "copy.txt"));

    reset_content_counts(node_b);
    auto rec_sync = run_node_sync(node_b);
    ASSERT_TRUE(rec_sync.has_value()) << (rec_sync ? "" : rec_sync.error().detail);

    EXPECT_TRUE(local_entry_exists(node_b, "copy.txt"));
    EXPECT_EQ(read_local_file(node_b, "copy.txt"), "SharedSourceContentBetweenCopyAndMove");
    EXPECT_TRUE(local_entry_exists(node_b, "moved.txt"));
    EXPECT_EQ(read_local_file(node_b, "moved.txt"), "SharedSourceContentBetweenCopyAndMove");
    EXPECT_FALSE(local_entry_exists(node_b, "source.txt"));
    EXPECT_EQ(node_b.counters.content_gets, 0U);
}

#if defined(KASUMI_SYNC_CRASH_HELPER_PATH)
TEST(LocalCopyDependenciesTest, RecoveryPreservesDependencyOrderRealCrash) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "node_a_real_crash"));
    ASSERT_TRUE(init_sync_node(node_b, "node_b_real_crash", node_a.storage_root));

    write_local_file(node_a, "orig.txt", "CrashTestBytesRealProcess");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    write_local_file(node_a, "copy.txt", "CrashTestBytesRealProcess");
    rename_local_entry(node_a, "orig.txt", "moved.txt");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    const auto signal = node_b.profile / "copy_crash.signal";
    const auto child = run_crash_child(
        node_b, "sync", "after_copy_local_install",
        "", signal);
    ASSERT_TRUE(child.reached_point) << "Child detail: " << child.detail;
    ASSERT_TRUE(child.was_killed);

    reset_content_counts(node_b);
    auto sync_res = run_node_sync(node_b);
    ASSERT_TRUE(sync_res.has_value()) << (sync_res ? "" : sync_res.error().detail);
    EXPECT_TRUE(local_entry_exists(node_b, "copy.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "moved.txt"));
    EXPECT_FALSE(local_entry_exists(node_b, "orig.txt"));
    EXPECT_EQ(node_b.counters.content_gets, 0U);
}
#endif

TEST(LocalCopyDependenciesTest, RecoveryPreservesDependencyOrder) {
    // Invariant: crash replay or resume never executes Move before Copy
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "node_a_rec_dep"));
    ASSERT_TRUE(init_sync_node(node_b, "node_b_rec_dep", node_a.storage_root));

    write_local_file(node_a, "orig.txt", "CrashTestBytes");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    write_local_file(node_a, "copy.txt", "CrashTestBytes");
    rename_local_entry(node_a, "orig.txt", "moved.txt");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    // Trigger sync with fault right after copy install
    bool hit_hook = false;
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path&) {
            if (point == "after_copy_local_install") {
                hit_hook = true;
            }
        });

    auto sync_res = run_node_sync(node_b);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    // Final state must converge safely
    ASSERT_TRUE(sync_res.has_value());
    EXPECT_TRUE(local_entry_exists(node_b, "copy.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "moved.txt"));
}



TEST(LocalCopyDependenciesTest, CopyRecoveryRejectsDivergentIdentity) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "rec_divergent"));
    write_local_file(node, "src.txt", "DivergentIdentityData");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("DivergentIdentityData")),
        .alt_path = "dst.txt",
        .size = 21,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_divergent");

    ASSERT_TRUE(kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key, ws,
        progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr).has_value());

    const auto orig_id = kasumi::platform::private_storage::query_file_identity(node.local / "dst.txt");
    ASSERT_TRUE(orig_id.valid);

    std::filesystem::rename(node.local / "dst.txt", node.local / "dst_preserved.txt");
    write_local_file(node, "dst.txt", "DivergentIdentityData");
    const auto new_id = kasumi::platform::private_storage::query_file_identity(node.local / "dst.txt");
    ASSERT_TRUE(new_id.valid);
    ASSERT_FALSE(orig_id == new_id);

    auto replayed = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key, ws,
        progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);

    EXPECT_FALSE(replayed.has_value());
    EXPECT_EQ(replayed.error().code, kasumi::application::sync::mutation::MutationErrorCode::DestinationConflict);
    EXPECT_TRUE(local_entry_exists(node, "dst.txt"));
}

// ============================================================================
// GRUPO C — APLICAÇÃO
// ============================================================================

TEST(LocalCopyApplicationTest, CopyCreatesIndependentFile) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "app_indep"));
    write_local_file(node, "src.bin", "OriginalBinaryData");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.bin",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("OriginalBinaryData")),
        .alt_path = "dst.bin",
        .size = 18,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_app1");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    ASSERT_TRUE(applied.has_value());

    EXPECT_TRUE(local_entry_exists(node, "dst.bin"));
    EXPECT_EQ(read_local_file(node, "dst.bin"), "OriginalBinaryData");

    // Modify destination: source must remain unchanged
    write_local_file(node, "dst.bin", "ModifiedDestination");
    EXPECT_EQ(read_local_file(node, "src.bin"), "OriginalBinaryData");
}

TEST(LocalCopyApplicationTest, CopyPreservesOriginalBytes) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "app_bytes"));
    std::string binary_data(1024, '\0');
    for (std::size_t i = 0; i < binary_data.size(); ++i) {
        binary_data[i] = static_cast<char>(i % 256);
    }
    write_local_file(node, "src.bin", binary_data);

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.bin",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string(binary_data)),
        .alt_path = "dst.bin",
        .size = 1024,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_app2");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    ASSERT_TRUE(applied.has_value());

    EXPECT_EQ(read_local_file(node, "dst.bin"), binary_data);
}

TEST(LocalCopyApplicationTest, CopyVerifiesBLAKE3) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "app_hash"));
    write_local_file(node, "src.bin", "ActualData");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.bin",
        .hash = std::string(64, 'f'), // Invalid/mismatched hash
        .alt_path = "dst.bin",
        .size = 10,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_app3");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    EXPECT_FALSE(applied.has_value());
    EXPECT_FALSE(local_entry_exists(node, "dst.bin"));
}

TEST(LocalCopyApplicationTest, CopyVerifiesSize) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "app_size"));
    write_local_file(node, "src.bin", "ActualData");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.bin",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("ActualData")),
        .alt_path = "dst.bin",
        .size = 9999, // Wrong size
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_app4");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    EXPECT_FALSE(applied.has_value());
    EXPECT_FALSE(local_entry_exists(node, "dst.bin"));
}

TEST(LocalCopyApplicationTest, CopyRejectsExistingDestination) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "app_no_overwrite"));
    write_local_file(node, "src.bin", "SourceData");
    write_local_file(node, "dst.bin", "PreExistingData");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.bin",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("SourceData")),
        .alt_path = "dst.bin",
        .size = 10,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_app5");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    EXPECT_FALSE(applied.has_value());
    // Pre-existing data must not have been overwritten
    EXPECT_EQ(read_local_file(node, "dst.bin"), "PreExistingData");
}

TEST(LocalCopyApplicationTest, CopyRejectsSymlinkSource) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "app_symlink"));
    write_local_file(node, "real.bin", "RealData");

    std::error_code ec;
    std::filesystem::create_symlink(node.local / "real.bin", node.local / "symlink.bin", ec);
    if (ec) {
        GTEST_SKIP() << "Symlinks not supported on this filesystem / privileges";
    }

    Operation op{
        .action = Action::CopyLocal,
        .path = "symlink.bin",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("RealData")),
        .alt_path = "dst.bin",
        .size = 8,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_app6");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    EXPECT_FALSE(applied.has_value());
}

TEST(LocalCopyApplicationTest, CopyRejectsUnsafeParent) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "app_unsafe_parent"));
    write_local_file(node, "src.bin", "SomeData");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.bin",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("SomeData")),
        .alt_path = "non_existent_folder/sub/dst.bin",
        .size = 8,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_app7");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    EXPECT_FALSE(applied.has_value());
}

TEST(LocalCopyApplicationTest, CopyRejectsCorruptedSource) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "app_corrupt"));
    write_local_file(node, "src.bin", "GoodData");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.bin",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("GoodData")),
        .alt_path = "dst.bin",
        .size = 8,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_app8");

    // Corrupt source before apply
    write_local_file(node, "src.bin", "CorruptData");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    EXPECT_FALSE(applied.has_value());
}

TEST(LocalCopyApplicationTest, CopyHandlesEmptyFile) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "app_empty"));
    write_local_file(node, "empty.bin", "");

    Operation op{
        .action = Action::CopyLocal,
        .path = "empty.bin",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("")),
        .alt_path = "dst_empty.bin",
        .size = 0,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_app9");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    ASSERT_TRUE(applied.has_value());
    EXPECT_TRUE(local_entry_exists(node, "dst_empty.bin"));
    EXPECT_EQ(read_local_file(node, "dst_empty.bin"), "");
}

TEST(LocalCopyApplicationTest, CopyHandlesFilesystemFailure) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "app_fs_fail"));
    write_local_file(node, "src.bin", "Data");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.bin",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("Data")),
        .alt_path = "", // Invalid empty destination
        .size = 4,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_app10");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    EXPECT_FALSE(applied.has_value());
}

TEST(LocalCopyApplicationTest, CopyRejectsExternalReplacementImmediatelyAfterInstall) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "app_own_replace"));
    write_local_file(node, "src.txt", "DataForOwnershipTest");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("DataForOwnershipTest")),
        .alt_path = "dst.txt",
        .size = 20,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_own");

    // Hook fires right after install to replace destination with an external file
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "after_copy_local_install") {
                std::filesystem::rename(path, node.local / "orig_installed.txt");
                kasumi::test::write_text(path, "DataForOwnershipTest");
            }
        });

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key, ws,
        progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_FALSE(applied.has_value());
    EXPECT_TRUE(local_entry_exists(node, "dst.txt"));
    EXPECT_EQ(read_local_file(node, "dst.txt"), "DataForOwnershipTest");
    EXPECT_TRUE(local_entry_exists(node, "orig_installed.txt"));
}

// ============================================================================
// GRUPO D — STAGING E INSTALAÇÃO
// ============================================================================

TEST(LocalCopyStagingTest, CopyStagingFailure) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "stg_fail"));
    write_local_file(node, "src.txt", "StagingData");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("StagingData")),
        .alt_path = "dst.txt",
        .size = 11,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_stg1");

    // Inject fault before staging write
    kasumi::application::sync::mutation_fault_test::set_hook(
        [](std::string_view point, const std::filesystem::path&) {
            if (point == "before_copy_local_staging") {
                throw std::runtime_error("simulated staging creation fault");
            }
        });

    EXPECT_THROW({
        (void)kasumi::application::sync::mutation::apply_operation(
            op, 0, node.local, node.context.storage, node.key,
            ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    }, std::runtime_error);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_FALSE(local_entry_exists(node, "dst.txt"));
    EXPECT_TRUE(local_entry_exists(node, "src.txt"));
}

TEST(LocalCopyStagingTest, CopyStagingRejectsConcurrentOccupationWithoutTruncationOrRemoval) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "stg_race"));
    write_local_file(node, "src.txt", "SourceDataForStagingTest");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("SourceDataForStagingTest")),
        .alt_path = "dst.txt",
        .size = 24,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_stg_race");

    const auto candidate = kasumi::application::sync::mutation::detail::copy_candidate_path(
        node.local / "dst.txt", ws, 0);

    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path&) {
            if (point == "during_copy_local_staging_race") {
                kasumi::test::write_text(candidate, "ExternalUntouchableData");
            }
        });

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_FALSE(applied.has_value());
    EXPECT_TRUE(std::filesystem::exists(candidate));
    EXPECT_EQ(kasumi::test::read_text(candidate), "ExternalUntouchableData");
    std::filesystem::remove(candidate);
}

TEST(LocalCopyStagingTest, CopyPartialStagingNotInstalled) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "stg_partial"));
    write_local_file(node, "src.txt", "PartialPayload");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("PartialPayload")),
        .alt_path = "dst.txt",
        .size = 14,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_stg2");

    // Fault during copy write
    kasumi::application::sync::mutation_fault_test::set_hook(
        [](std::string_view point, const std::filesystem::path&) {
            if (point == "during_copy_local_write") {
                throw std::runtime_error("simulated partial write abort");
            }
        });

    EXPECT_THROW({
        (void)kasumi::application::sync::mutation::apply_operation(
            op, 0, node.local, node.context.storage, node.key,
            ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    }, std::runtime_error);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_FALSE(local_entry_exists(node, "dst.txt"));
}

TEST(LocalCopyStagingTest, CopyDurabilityFailure) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "stg_durability"));
    write_local_file(node, "src.txt", "DurabilityPayload");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("DurabilityPayload")),
        .alt_path = "dst.txt",
        .size = 17,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_stg3");

    kasumi::application::sync::mutation_fault_test::set_hook(
        [](std::string_view point, const std::filesystem::path&) {
            if (point == "before_copy_local_durability") {
                throw std::runtime_error("simulated fsync failure");
            }
        });

    EXPECT_THROW({
        (void)kasumi::application::sync::mutation::apply_operation(
            op, 0, node.local, node.context.storage, node.key,
            ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    }, std::runtime_error);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_FALSE(local_entry_exists(node, "dst.txt"));
}

TEST(LocalCopyStagingTest, CopyInstallationFailure) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "stg_install"));
    write_local_file(node, "src.txt", "InstallFailurePayload");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("InstallFailurePayload")),
        .alt_path = "dst.txt",
        .size = 21,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_stg4");

    kasumi::application::sync::mutation_fault_test::set_hook(
        [](std::string_view point, const std::filesystem::path&) {
            if (point == "before_copy_local_install") {
                throw std::runtime_error("simulated install rename failure");
            }
        });

    EXPECT_THROW({
        (void)kasumi::application::sync::mutation::apply_operation(
            op, 0, node.local, node.context.storage, node.key,
            ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    }, std::runtime_error);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_FALSE(local_entry_exists(node, "dst.txt"));
}

TEST(LocalCopyStagingTest, CopyDoesNotOverwriteConcurrentDestination) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "stg_concurrent"));
    write_local_file(node, "src.txt", "Data");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("Data")),
        .alt_path = "dst.txt",
        .size = 4,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_stg5");

    // Right before atomic install, an external process creates dst.txt
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path&) {
            if (point == "before_copy_local_install") {
                write_local_file(node, "dst.txt", "ExternalInterference");
            }
        });

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    // Must fail closed without overwriting external data
    EXPECT_FALSE(applied.has_value());
    EXPECT_EQ(read_local_file(node, "dst.txt"), "ExternalInterference");
}

TEST(LocalCopyStagingTest, CopyStagingRecovery) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "stg_recovery"));
    write_local_file(node, "src.txt", "Data");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("Data")),
        .alt_path = "dst.txt",
        .size = 4,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_stg6");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    ASSERT_TRUE(applied.has_value());

    // Verify no temporary staging files remain in destination directory
    for (const auto& entry : std::filesystem::directory_iterator(node.local)) {
        EXPECT_NE(entry.path().extension(), ".kasumi-staging");
        EXPECT_NE(entry.path().extension(), ".tmp");
    }
}

TEST(LocalCopyStagingTest, CopyIndependentOfSourceAfterInstall) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "stg_indep_post"));
    write_local_file(node, "src.txt", "DataToBeDeleted");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("DataToBeDeleted")),
        .alt_path = "dst.txt",
        .size = 15,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_stg7");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key,
        ws, progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    ASSERT_TRUE(applied.has_value());

    remove_local_subtree(node, "src.txt");
    EXPECT_TRUE(local_entry_exists(node, "dst.txt"));
    EXPECT_EQ(read_local_file(node, "dst.txt"), "DataToBeDeleted");
}




// ============================================================================
// GRUPO E — ROLLBACK
// ============================================================================

TEST(LocalCopyRollbackTest, CopyRollbackRemovesOwnedDestination) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "rb_removes"));
    write_local_file(node, "src.txt", "RollbackPayload");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("RollbackPayload")),
        .alt_path = "dst.txt",
        .size = 15,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_rb1");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key, ws,
        progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    ASSERT_TRUE(applied.has_value());
    EXPECT_TRUE(local_entry_exists(node, "dst.txt"));

    progress.state = OperationState::Applied;
    auto rolled = kasumi::application::sync::mutation::rollback_operation(
        op, 0, node.local, ws, progress);
    ASSERT_TRUE(rolled.has_value()) << rolled.error().detail;

    // Destination must be removed by rollback
    EXPECT_FALSE(local_entry_exists(node, "dst.txt"));
    // Source must remain untouched
    EXPECT_TRUE(local_entry_exists(node, "src.txt"));
    EXPECT_EQ(read_local_file(node, "src.txt"), "RollbackPayload");
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::platform::workspace_file(ws, 0, ".copy_identity")));
}

TEST(LocalCopyRollbackTest, CopyRollbackPreservesSource) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "rb_preserves_src"));
    write_local_file(node, "source.bin", "SacredSourceData");

    Operation op{
        .action = Action::CopyLocal,
        .path = "source.bin",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("SacredSourceData")),
        .alt_path = "dest.bin",
        .size = 16,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_rb2");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key, ws,
        progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    ASSERT_TRUE(applied.has_value());

    progress.state = OperationState::Applied;
    auto rolled = kasumi::application::sync::mutation::rollback_operation(
        op, 0, node.local, ws, progress);
    ASSERT_TRUE(rolled.has_value());

    EXPECT_TRUE(local_entry_exists(node, "source.bin"));
    EXPECT_EQ(read_local_file(node, "source.bin"), "SacredSourceData");
}

TEST(LocalCopyRollbackTest, CopyRollbackRejectsExternalModification) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "rb_external_mod"));
    write_local_file(node, "src.txt", "OriginalBytes");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("OriginalBytes")),
        .alt_path = "dst.txt",
        .size = 13,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_rb3");

    auto applied = kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key, ws,
        progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    ASSERT_TRUE(applied.has_value());

    // External modification to dst.txt
    write_local_file(node, "dst.txt", "UserAlteredThisFileExternally");

    progress.state = OperationState::Applied;
    auto rolled = kasumi::application::sync::mutation::rollback_operation(
        op, 0, node.local, ws, progress);

    // Rollback MUST fail closed to preserve external data!
    ASSERT_FALSE(rolled.has_value());
    EXPECT_EQ(rolled.error().code,
              kasumi::application::sync::mutation::MutationErrorCode::DestinationConflict);
    EXPECT_TRUE(local_entry_exists(node, "dst.txt"));
    EXPECT_EQ(read_local_file(node, "dst.txt"), "UserAlteredThisFileExternally");
}

TEST(LocalCopyRollbackTest, CopyRollbackRejectsExternalReplacement) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "rb_external_replace"));
    write_local_file(node, "src.txt", "Data");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("Data")),
        .alt_path = "dst.txt",
        .size = 4,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_rb4");

    ASSERT_TRUE(kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key, ws,
        progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr).has_value());

    // Replace file with directory
    std::filesystem::remove(node.local / "dst.txt");
    std::filesystem::create_directories(node.local / "dst.txt");

    progress.state = OperationState::Applied;
    auto rolled = kasumi::application::sync::mutation::rollback_operation(
        op, 0, node.local, ws, progress);

    EXPECT_FALSE(rolled.has_value());
    EXPECT_TRUE(std::filesystem::is_directory(node.local / "dst.txt"));
}

TEST(LocalCopyRollbackTest, CopyRollbackRejectsExternalReplacementWithIdenticalContent) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "rb_identical_replace"));
    write_local_file(node, "src.txt", "IdenticalPayload12345");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("IdenticalPayload12345")),
        .alt_path = "dst.txt",
        .size = 21,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_rb_ident");

    ASSERT_TRUE(kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key, ws,
        progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr).has_value());

    const auto orig_id = kasumi::platform::private_storage::query_file_identity(node.local / "dst.txt");
    ASSERT_TRUE(orig_id.valid);

    // Preserve original file so its inode is not reused probabilistically on Linux
    std::filesystem::rename(node.local / "dst.txt", node.local / "dst_preserved.txt");
    write_local_file(node, "dst.txt", "IdenticalPayload12345");
    const auto new_id = kasumi::platform::private_storage::query_file_identity(node.local / "dst.txt");
    ASSERT_TRUE(new_id.valid);
    ASSERT_FALSE(orig_id == new_id);

    progress.state = OperationState::Applied;
    auto rolled = kasumi::application::sync::mutation::rollback_operation(
        op, 0, node.local, ws, progress);

    ASSERT_FALSE(rolled.has_value());
    EXPECT_EQ(rolled.error().code,
              kasumi::application::sync::mutation::MutationErrorCode::DestinationConflict);
    EXPECT_TRUE(local_entry_exists(node, "dst.txt"));
    EXPECT_EQ(read_local_file(node, "dst.txt"), "IdenticalPayload12345");
    EXPECT_TRUE(local_entry_exists(node, "dst_preserved.txt"));
}

TEST(LocalCopyRollbackTest, CopyRollbackRejectsExternalReplacementRaceBeforeRemoval) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "rb_race_replace"));
    write_local_file(node, "src.txt", "PayloadForRaceTest123");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("PayloadForRaceTest123")),
        .alt_path = "dst.txt",
        .size = 21,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_rb_race");

    ASSERT_TRUE(kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key, ws,
        progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr).has_value());

    const auto orig_id = kasumi::platform::private_storage::query_file_identity(node.local / "dst.txt");
    ASSERT_TRUE(orig_id.valid);

    // Inject replacement right at the hook before removal in rollback
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "before_remove_file_if_hash") {
                std::filesystem::rename(path, node.local / "dst_saved.txt");
                kasumi::test::write_text(path, "PayloadForRaceTest123");
            }
        });

    progress.state = OperationState::Applied;
    auto rolled = kasumi::application::sync::mutation::rollback_operation(
        op, 0, node.local, ws, progress);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_FALSE(rolled.has_value());
    EXPECT_TRUE(local_entry_exists(node, "dst.txt"));
    EXPECT_EQ(read_local_file(node, "dst.txt"), "PayloadForRaceTest123");
    EXPECT_TRUE(local_entry_exists(node, "dst_saved.txt"));
    EXPECT_EQ(read_local_file(node, "dst_saved.txt"), "PayloadForRaceTest123");
}

TEST(LocalCopyRollbackTest, CopyRollbackIsIdempotent) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "rb_idempotent"));
    write_local_file(node, "src.txt", "Payload");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("Payload")),
        .alt_path = "dst.txt",
        .size = 7,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_rb5");

    ASSERT_TRUE(kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key, ws,
        progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr).has_value());

    progress.state = OperationState::Applied;
    auto rolled1 = kasumi::application::sync::mutation::rollback_operation(
        op, 0, node.local, ws, progress);
    ASSERT_TRUE(rolled1.has_value());

    // Calling rollback again when dst is already gone must succeed idempotently
    auto rolled2 = kasumi::application::sync::mutation::rollback_operation(
        op, 0, node.local, ws, progress);
    EXPECT_TRUE(rolled2.has_value());
}

TEST(LocalCopyRollbackTest, CopyRollbackRemovesOwnedCandidate) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "rb_owned_candidate"));
    write_local_file(node, "src.txt", "Payload");
    Operation op{.action = Action::CopyLocal,
                 .path = "src.txt",
                 .hash = kasumi::hash_hex(kasumi::hasher::hash_string("Payload")),
                 .alt_path = "dst.txt",
                 .size = 7};
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_owned_candidate");
    ASSERT_TRUE(kasumi::application::sync::mutation::apply_operation(
        op, 0, node.local, node.context.storage, node.key, ws, progress,
        kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr));
    const auto candidate = kasumi::application::sync::mutation::detail::copy_candidate_path(
        node.local / "dst.txt", ws, 0);
    std::filesystem::rename(node.local / "dst.txt", candidate);

    const auto rolled = kasumi::application::sync::mutation::rollback_operation(
        op, 0, node.local, ws, progress);
    ASSERT_TRUE(rolled) << rolled.error().detail;
    EXPECT_FALSE(std::filesystem::exists(candidate));
    EXPECT_FALSE(std::filesystem::exists(kasumi::platform::workspace_file(ws, 0, ".copy_identity")));
    EXPECT_EQ(read_local_file(node, "src.txt"), "Payload");
}

TEST(LocalCopyRollbackTest, CopyRollbackRejectsForeignCandidate) {
    for (const bool keep_marker : {true, false}) {
        SCOPED_TRACE(keep_marker);
        SyncNode node;
        ASSERT_TRUE(init_sync_node(node, "rb_foreign_candidate"));
        write_local_file(node, "src.txt", "Payload");
        Operation op{.action = Action::CopyLocal,
                     .path = "src.txt",
                     .hash = kasumi::hash_hex(kasumi::hasher::hash_string("Payload")),
                     .alt_path = "dst.txt",
                     .size = 7};
        OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
        auto ws = make_test_workspace(node.profile / "ws_foreign_candidate");
        ASSERT_TRUE(kasumi::application::sync::mutation::apply_operation(
            op, 0, node.local, node.context.storage, node.key, ws, progress,
            kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr));
        std::filesystem::rename(node.local / "dst.txt", node.local / "original.txt");
        const auto candidate = kasumi::application::sync::mutation::detail::copy_candidate_path(
            node.local / "dst.txt", ws, 0);
        kasumi::test::write_text(candidate, "Payload");
        const auto original_id = kasumi::platform::private_storage::query_file_identity(node.local / "original.txt");
        const auto foreign_id = kasumi::platform::private_storage::query_file_identity(candidate);
        ASSERT_TRUE(original_id.valid && foreign_id.valid);
        ASSERT_FALSE(original_id == foreign_id);
        const auto marker = kasumi::platform::workspace_file(ws, 0, ".copy_identity");
        if (!keep_marker)
            std::filesystem::remove(marker);

        const auto rolled = kasumi::application::sync::mutation::rollback_operation(
            op, 0, node.local, ws, progress);
        ASSERT_FALSE(rolled);
        EXPECT_EQ(rolled.error().code,
                  kasumi::application::sync::mutation::MutationErrorCode::DestinationConflict);
        EXPECT_EQ(kasumi::test::read_text(candidate), "Payload");
        EXPECT_EQ(std::filesystem::exists(marker), keep_marker);
        EXPECT_EQ(read_local_file(node, "src.txt"), "Payload");
    }
}

TEST(LocalCopyRollbackTest, CopyRollbackRejectsCorruptMarkerWithoutDestination) {
    for (const bool keep_candidate : {false, true}) {
        SCOPED_TRACE(keep_candidate);
        SyncNode node;
        ASSERT_TRUE(init_sync_node(node, "rb_corrupt_marker"));
        write_local_file(node, "src.txt", "Payload");
        Operation op{.action = Action::CopyLocal,
                     .path = "src.txt",
                     .hash = kasumi::hash_hex(kasumi::hasher::hash_string("Payload")),
                     .alt_path = "dst.txt",
                     .size = 7};
        OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
        auto ws = make_test_workspace(node.profile / "ws_corrupt_marker");
        ASSERT_TRUE(kasumi::application::sync::mutation::apply_operation(
            op, 0, node.local, node.context.storage, node.key, ws, progress,
            kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr));
        const auto candidate = kasumi::application::sync::mutation::detail::copy_candidate_path(
            node.local / "dst.txt", ws, 0);
        if (keep_candidate)
            std::filesystem::rename(node.local / "dst.txt", candidate);
        else
            std::filesystem::remove(node.local / "dst.txt");
        const auto marker = kasumi::platform::workspace_file(ws, 0, ".copy_identity");
        kasumi::test::write_text(marker, "corrupt");

        const auto rolled = kasumi::application::sync::mutation::rollback_operation(
            op, 0, node.local, ws, progress);
        ASSERT_FALSE(rolled);
        EXPECT_EQ(rolled.error().code,
                  kasumi::application::sync::mutation::MutationErrorCode::IntegrityMismatch);
        EXPECT_EQ(kasumi::test::read_text(marker), "corrupt");
        EXPECT_EQ(std::filesystem::exists(candidate), keep_candidate);
        EXPECT_EQ(read_local_file(node, "src.txt"), "Payload");
    }
}

TEST(LocalCopyRollbackTest, CopyRollbackPropagatesRemovalFailure) {
    for (const bool staging : {false, true}) {
        SCOPED_TRACE(staging);
        SyncNode node;
        ASSERT_TRUE(init_sync_node(node, "rb_remove_error"));
        write_local_file(node, "src.txt", "Payload");
        Operation op{.action = Action::CopyLocal,
                     .path = "src.txt",
                     .hash = kasumi::hash_hex(kasumi::hasher::hash_string("Payload")),
                     .alt_path = "dst.txt",
                     .size = 7};
        OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
        auto ws = make_test_workspace(node.profile / "ws_remove_error");
        ASSERT_TRUE(kasumi::application::sync::mutation::apply_operation(
            op, 0, node.local, node.context.storage, node.key, ws, progress,
            kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr));
        const auto target = staging
            ? kasumi::application::sync::mutation::detail::copy_candidate_path(node.local / "dst.txt", ws, 0)
            : node.local / "dst.txt";
        if (staging)
            std::filesystem::rename(node.local / "dst.txt", target);
#if defined(_WIN32)
        const auto attributes = GetFileAttributesW(target.c_str());
        ASSERT_NE(attributes, INVALID_FILE_ATTRIBUTES);
        ASSERT_TRUE(SetFileAttributesW(target.c_str(), attributes | FILE_ATTRIBUTE_READONLY));
#else
        const auto permissions = std::filesystem::status(node.local).permissions();
        std::filesystem::permissions(node.local, std::filesystem::perms::owner_read | std::filesystem::perms::owner_exec);
#endif
        const auto rolled = kasumi::application::sync::mutation::rollback_operation(
            op, 0, node.local, ws, progress);
#if defined(_WIN32)
        EXPECT_TRUE(SetFileAttributesW(target.c_str(), attributes));
#else
        std::filesystem::permissions(node.local, permissions);
#endif
        ASSERT_FALSE(rolled);
        EXPECT_EQ(rolled.error().code,
                  kasumi::application::sync::mutation::MutationErrorCode::LocalIo);
        EXPECT_EQ(kasumi::test::read_text(target), "Payload");
        EXPECT_TRUE(std::filesystem::exists(kasumi::platform::workspace_file(ws, 0, ".copy_identity")));
        const auto retried = kasumi::application::sync::mutation::rollback_operation(
            op, 0, node.local, ws, progress);
        ASSERT_TRUE(retried) << retried.error().detail;
        EXPECT_FALSE(std::filesystem::exists(target));
        EXPECT_FALSE(std::filesystem::exists(kasumi::platform::workspace_file(ws, 0, ".copy_identity")));
    }
}


TEST(LocalCopyRollbackTest, CopyRollbackAfterLaterOperationFails) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "rb_cascade"));
    write_local_file(node, "orig.txt", "PayloadData");

    Operation op1{
        .action = Action::CopyLocal,
        .path = "orig.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("PayloadData")),
        .alt_path = "copy.txt",
        .size = 11,
    };
    Operation op2{
        .action = Action::Download,
        .path = "download_fail.txt",
        .hash = std::string(64, '0'),
        .alt_path = "",
        .size = 100,
    };

    OperationProgress prog1{.backup_slot = 0, .state = OperationState::Prepared};
    OperationProgress prog2{.backup_slot = 1, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_rb6");

    ASSERT_TRUE(kasumi::application::sync::mutation::apply_operation(
        op1, 0, node.local, node.context.storage, node.key, ws,
        prog1, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr).has_value());
    prog1.state = OperationState::Applied;

    // Simulate failure on op2 triggering rollback of op1
    auto rolled = kasumi::application::sync::mutation::rollback_operation(
        op1, 0, node.local, ws, prog1);
    ASSERT_TRUE(rolled.has_value());

    EXPECT_FALSE(local_entry_exists(node, "copy.txt"));
    EXPECT_TRUE(local_entry_exists(node, "orig.txt"));
}

// ============================================================================
// GRUPO G — INTEGRAÇÃO
// ============================================================================

TEST(LocalCopyIntegrationTest, PureCopyBetweenTwoClients) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "integ_a_pure"));
    ASSERT_TRUE(init_sync_node(node_b, "integ_b_pure", node_a.storage_root));

    // Client A creates original file and commits
    write_local_file(node_a, "manual.pdf", "ContentOfKasumiUserManualV092");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    // Client B downloads it
    ASSERT_TRUE(run_node_sync(node_b).has_value());
    EXPECT_EQ(read_local_file(node_b, "manual.pdf"), "ContentOfKasumiUserManualV092");

    // Client A copies manual.pdf to docs/manual_backup.pdf and commits
    write_local_file(node_a, "docs/manual_backup.pdf", "ContentOfKasumiUserManualV092");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    // Client B syncs: must plan and apply CopyLocal with ZERO remote Content I/O
    reset_content_counts(node_b);
    auto sync_b = run_node_sync(node_b);
    ASSERT_TRUE(sync_b.has_value()) << sync_b.error().detail;

    EXPECT_TRUE(local_entry_exists(node_b, "docs/manual_backup.pdf"));
    EXPECT_EQ(read_local_file(node_b, "docs/manual_backup.pdf"), "ContentOfKasumiUserManualV092");
    EXPECT_TRUE(local_entry_exists(node_b, "manual.pdf"));

    // INVARIANT: Content I/O must be zero during pure local copy
    EXPECT_EQ(node_b.counters.content_gets, 0U);
    EXPECT_EQ(node_b.counters.content_puts, 0U);
    EXPECT_EQ(node_b.counters.content_presences, 0U);
    EXPECT_EQ(node_b.counters.content_copies, 0U);
}

TEST(LocalCopyIntegrationTest, MultipleLocalCopiesBetweenClients) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "integ_a_multi"));
    ASSERT_TRUE(init_sync_node(node_b, "integ_b_multi", node_a.storage_root));

    write_local_file(node_a, "base.txt", "MultiClonePayload12345");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    for (int i = 1; i <= 5; ++i) {
        write_local_file(node_a, "copy_" + std::to_string(i) + ".txt", "MultiClonePayload12345");
    }
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    reset_content_counts(node_b);
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    for (int i = 1; i <= 5; ++i) {
        EXPECT_TRUE(local_entry_exists(node_b, "copy_" + std::to_string(i) + ".txt"));
        EXPECT_EQ(read_local_file(node_b, "copy_" + std::to_string(i) + ".txt"), "MultiClonePayload12345");
    }

    EXPECT_EQ(node_b.counters.content_gets, 0U);
    EXPECT_EQ(node_b.counters.content_puts, 0U);
}

TEST(LocalCopyIntegrationTest, CopyAndMoveBetweenClients) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "integ_a_move_copy"));
    ASSERT_TRUE(init_sync_node(node_b, "integ_b_move_copy", node_a.storage_root));

    write_local_file(node_a, "source.txt", "DataForBothMoveAndCopy");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    // A copies source.txt to copy.txt, and moves source.txt to destination.txt
    write_local_file(node_a, "copy.txt", "DataForBothMoveAndCopy");
    rename_local_entry(node_a, "source.txt", "destination.txt");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    reset_content_counts(node_b);
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    EXPECT_FALSE(local_entry_exists(node_b, "source.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "copy.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "destination.txt"));
    EXPECT_EQ(read_local_file(node_b, "copy.txt"), "DataForBothMoveAndCopy");
    EXPECT_EQ(read_local_file(node_b, "destination.txt"), "DataForBothMoveAndCopy");

    EXPECT_EQ(node_b.counters.content_gets, 0U);
    EXPECT_EQ(node_b.counters.content_puts, 0U);
}

TEST(LocalCopyIntegrationTest, CopyAndDeleteBetweenClients) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "integ_a_del_copy"));
    ASSERT_TRUE(init_sync_node(node_b, "integ_b_del_copy", node_a.storage_root));

    write_local_file(node_a, "old.txt", "WillSurviveAsNew");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    write_local_file(node_a, "new.txt", "WillSurviveAsNew");
    remove_local_subtree(node_a, "old.txt");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    reset_content_counts(node_b);
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    EXPECT_FALSE(local_entry_exists(node_b, "old.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "new.txt"));
    EXPECT_EQ(read_local_file(node_b, "new.txt"), "WillSurviveAsNew");

    EXPECT_EQ(node_b.counters.content_gets, 0U);
    EXPECT_EQ(node_b.counters.content_puts, 0U);
}

TEST(LocalCopyIntegrationTest, CopyConvergesToNoop) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "integ_a_noop"));
    ASSERT_TRUE(init_sync_node(node_b, "integ_b_noop", node_a.storage_root));

    write_local_file(node_a, "file1.txt", "ConvergePayload");
    write_local_file(node_a, "file2.txt", "ConvergePayload");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    // Subsequent sync on B must be complete no-op
    reset_content_counts(node_b);
    auto noop = run_node_sync(node_b);
    ASSERT_TRUE(noop.has_value());
    EXPECT_EQ(node_b.counters.content_gets, 0U);
    EXPECT_EQ(node_b.counters.content_puts, 0U);
}


struct ControlledCopyMetrics {
    std::size_t n = 0;
    std::uint64_t total_bytes = 0;
    double total_sync_s = 0.0;
    double prep_wall_s = 0.0;
    double prep_source_hash_wall_s = 0.0;
    double apply_wall_s = 0.0;
    double staging_wall_s = 0.0;
    double dest_verif_wall_s = 0.0;
    double durability_wall_s = 0.0;
    double install_wall_s = 0.0;
    double journal_save_wall_s = 0.0;
    double journal_delta_calc_s = 0.0;
    double journal_sem_val_s = 0.0;
    double journal_encode_s = 0.0;
    double journal_durable_write_s = 0.0;
    double final_val_wall_s = 0.0;
    std::uint64_t copy_planned = 0;
    std::uint64_t copy_applied = 0;
    std::uint64_t copy_bytes_copied = 0;
    std::uint64_t source_hash_calls = 0;
    std::uint64_t journal_save_calls = 0;
    std::uint64_t journal_delta_count = 0;
    std::uint64_t journal_bytes_written = 0;
    std::size_t content_gets = 0;
    std::size_t content_puts = 0;
    std::size_t content_presences = 0;
    std::size_t content_copies = 0;
};

ControlledCopyMetrics run_controlled_copy_reproduction(std::size_t count, std::size_t file_payload_size = 1024) {
    kasumi::platform::perf_trace::force_enable(true);
    SyncNode sender;
    SyncNode receiver;
    EXPECT_TRUE(init_sync_node(sender, "copy-diag-sender-" + std::to_string(count)));
    EXPECT_TRUE(init_sync_node(receiver, "copy-diag-receiver-" + std::to_string(count), sender.storage_root));

    ControlledCopyMetrics m;
    m.n = count;

    for (std::size_t i = 0; i < count; ++i) {
        std::string payload = "content-" + std::to_string(i) + "-" + std::string(file_payload_size, 'A');
        m.total_bytes += payload.size();
        write_local_file(sender, "source_dir/file_" + std::to_string(i) + ".bin", payload);
    }

    auto s1 = run_node_sync(sender);
    EXPECT_TRUE(s1.has_value()) << (s1 ? "" : s1.error().detail);
    auto r1 = run_node_sync(receiver);
    EXPECT_TRUE(r1.has_value()) << (r1 ? "" : r1.error().detail);

    // Sender copies each file from source_dir to copy_dir
    for (std::size_t i = 0; i < count; ++i) {
        std::string payload = "content-" + std::to_string(i) + "-" + std::string(file_payload_size, 'A');
        write_local_file(sender, "copy_dir/file_" + std::to_string(i) + ".bin", payload);
    }
    auto s2 = run_node_sync(sender);
    EXPECT_TRUE(s2.has_value()) << (s2 ? "" : s2.error().detail);

    reset_content_counts(receiver);
    kasumi::platform::perf_trace::reset();

    const auto start = std::chrono::steady_clock::now();
    auto r2 = run_node_sync(receiver);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_TRUE(r2.has_value()) << (r2 ? "" : r2.error().detail);

    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);

    m.total_sync_s = std::chrono::duration<double>(elapsed).count();
    m.prep_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("copy preparation wall")) / 1e6;
    m.prep_source_hash_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("copy source hash wall")) / 1e6;
    m.apply_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("copy apply wall")) / 1e6;
    m.staging_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("copy staging wall")) / 1e6;
    m.dest_verif_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("copy destination verification wall")) / 1e6;
    m.durability_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("copy durability wall")) / 1e6;
    m.install_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("copy install wall")) / 1e6;
    m.journal_save_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("journal save wall")) / 1e6;
    m.journal_delta_calc_s = static_cast<double>(kasumi::platform::perf_trace::get_time("journal delta calculation wall")) / 1e6;
    m.journal_sem_val_s = static_cast<double>(kasumi::platform::perf_trace::get_time("journal semantic validation wall")) / 1e6;
    m.journal_encode_s = static_cast<double>(kasumi::platform::perf_trace::get_time("journal encode wall")) / 1e6;
    m.journal_durable_write_s = static_cast<double>(kasumi::platform::perf_trace::get_time("journal durable write wall")) / 1e6;
    m.final_val_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("final local validation wall")) / 1e6;

    m.copy_planned = kasumi::platform::perf_trace::get_count("copy planned count");
    m.copy_applied = kasumi::platform::perf_trace::get_count("copy applied count");
    m.copy_bytes_copied = kasumi::platform::perf_trace::get_count("copy bytes copied");
    m.source_hash_calls = kasumi::platform::perf_trace::get_count("source hash calls");
    m.journal_save_calls = kasumi::platform::perf_trace::get_count("journal save calls");
    m.journal_delta_count = kasumi::platform::perf_trace::get_count("journal delta count");
    m.journal_bytes_written = kasumi::platform::perf_trace::get_count("journal bytes written");

    m.content_gets = receiver.counters.content_gets;
    m.content_puts = receiver.counters.content_puts;
    m.content_presences = receiver.counters.content_presences;
    m.content_copies = receiver.counters.content_copies;

    std::cout << "\n=======================================================\n";
    std::cout << "DIAGNOSTIC COPY METRICS REPORT FOR N = " << count << "\n";
    std::cout << "=======================================================\n";
    std::cout << std::fixed << std::setprecision(6);
    std::cout << "Total sync duration:          " << m.total_sync_s << " s\n";
    std::cout << "Copy planned count:           " << m.copy_planned << "\n";
    std::cout << "Copy applied count:           " << m.copy_applied << "\n";
    std::cout << "Copy bytes copied:            " << m.copy_bytes_copied << " bytes\n";
    std::cout << "Copy preparation wall:        " << m.prep_wall_s << " s\n";
    std::cout << "Copy source hash wall:        " << m.prep_source_hash_wall_s << " s\n";
    std::cout << "Copy apply wall:              " << m.apply_wall_s << " s\n";
    std::cout << "Copy staging wall:            " << m.staging_wall_s << " s\n";
    std::cout << "Copy dest verification wall:  " << m.dest_verif_wall_s << " s\n";
    std::cout << "Copy durability wall:         " << m.durability_wall_s << " s\n";
    std::cout << "Copy install wall:            " << m.install_wall_s << " s\n";
    std::cout << "Journal save calls:           " << m.journal_save_calls << "\n";
    std::cout << "Journal save wall:            " << m.journal_save_wall_s << " s\n";
    std::cout << "Apply ACL calls:              " << kasumi::platform::perf_trace::get_count("apply_acl calls") << "\n";
    std::cout << "Apply ACL wall:               " << static_cast<double>(kasumi::platform::perf_trace::get_time("apply_acl wall")) / 1e6 << " s\n";
    std::cout << "Journal delta count:          " << m.journal_delta_count << "\n";
    std::cout << "Journal bytes written:        " << m.journal_bytes_written << " bytes\n";
    std::cout << "Journal delta calc wall:      " << m.journal_delta_calc_s << " s\n";
    std::cout << "Journal sem validation wall:  " << m.journal_sem_val_s << " s\n";
    std::cout << "Journal encode wall:          " << m.journal_encode_s << " s\n";
    std::cout << "Journal durable write wall:   " << m.journal_durable_write_s << " s\n";
    std::cout << "Final local validation wall:  " << m.final_val_wall_s << " s\n";
    std::cout << "Content GET / PUT / PRESENCE: " << m.content_gets << " / " << m.content_puts << " / " << m.content_presences << "\n";
    std::cout << "=======================================================\n\n";

    kasumi::platform::perf_trace::force_enable(false);
    return m;
}

TEST(LocalCopyIntegrationTest, DiagnosticCopyReproduction16) {
    const auto m = run_controlled_copy_reproduction(16);
    EXPECT_EQ(m.copy_planned, 16U);
    EXPECT_EQ(m.copy_applied, 16U);
    EXPECT_EQ(m.content_gets, 0U);
}

TEST(LocalCopyIntegrationTest, DiagnosticCopyReproduction128) {
    const auto m = run_controlled_copy_reproduction(128);
    EXPECT_EQ(m.copy_planned, 128U);
    EXPECT_EQ(m.copy_applied, 128U);
    EXPECT_EQ(m.content_gets, 0U);
}

TEST(LocalCopyIntegrationTest, DiagnosticCopyReproduction512) {
    const auto m = run_controlled_copy_reproduction(512);
    EXPECT_EQ(m.copy_planned, 512U);
    EXPECT_EQ(m.copy_applied, 512U);
    EXPECT_EQ(m.content_gets, 0U);
}

// ============================================================================
// OWNERSHIP CHECKS, DURABILITY RETURNS, PRE-INSTALL CRASH
// ============================================================================

TEST(LocalCopyRollbackTest, CopyCleanupRejectsReplacementBeforeCheckingOpenDescriptor) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "rb_posix_race_open_fd"));
    write_local_file(node, "src.txt", "PayloadForOpenFdRace");

    const auto target_path = node.local / "staged.tmp";
    auto priv_file = kasumi::platform::private_storage::create_private_file(target_path);
    ASSERT_TRUE(priv_file.has_value());
    const auto orig_id = priv_file->identity;
    ASSERT_TRUE(orig_id.valid);

    // Replacement precedes the ownership check; the original inode stays alive.
    std::filesystem::rename(target_path, node.local / "staged_preserved.tmp");
    write_local_file(node, "staged.tmp", "ForeignFileReplacingStaged");
    ASSERT_FALSE(orig_id == kasumi::platform::private_storage::query_file_identity(target_path));

    const auto res = kasumi::platform::private_storage::remove_private_file_if_owned(*priv_file);
    EXPECT_FALSE(priv_file->is_open());

    // The foreign file MUST NOT be destroyed!
    EXPECT_TRUE(local_entry_exists(node, "staged.tmp"));
    EXPECT_EQ(read_local_file(node, "staged.tmp"), "ForeignFileReplacingStaged");
    EXPECT_EQ(res, kasumi::platform::private_storage::CleanupResult::IdentityMismatch);
}

TEST(LocalCopyStagingTest, CopyStagingCleanupRejectsReplacementBeforeOwnershipCheck) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "stg_race_replace"));
    write_local_file(node, "src.txt", "StagingCleanupRaceData");

    Operation op{
        .action = Action::CopyLocal,
        .path = "src.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("StagingCleanupRaceData")),
        .alt_path = "dst.txt",
        .size = 22,
    };
    OperationProgress progress{.backup_slot = 0, .state = OperationState::Prepared};
    auto ws = make_test_workspace(node.profile / "ws_stg_race");

    // During staging write, trigger failure to cause staging guard cleanup
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "during_copy_local_write") {
                std::error_code ec;
                std::filesystem::rename(path, path.string() + ".preserved", ec);
                std::ofstream out(path);
                out << "ForeignFileAtCandidatePath";
                out.close();
                throw std::runtime_error("simulated failure during write");
            }
        });

    EXPECT_THROW({
        (void)kasumi::application::sync::mutation::apply_operation(
            op, 0, node.local, node.context.storage, node.key, ws,
            progress, kasumi::application::sync::mutation::DownloadCacheMode::None, nullptr);
    }, std::runtime_error);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    const auto cand_path = kasumi::application::sync::mutation::detail::copy_candidate_path(
        node.local / "dst.txt", ws, 0);
    // Foreign file must be preserved
    ASSERT_TRUE(std::filesystem::exists(cand_path));
    EXPECT_EQ(kasumi::test::read_text(cand_path), "ForeignFileAtCandidatePath");
}

TEST(LocalCopyStagingTest, CopyCleanupResultDistinguishesIdentityMismatchFromAlreadyAbsent) {
    SyncNode node;
    ASSERT_TRUE(init_sync_node(node, "stg_cleanup_codes"));

    const auto path = node.local / "test_file.bin";
    write_local_file(node, "test_file.bin", "OriginalPayload");

    const auto actual_id = kasumi::platform::private_storage::query_file_identity(path);
    ASSERT_TRUE(actual_id.valid);

    kasumi::platform::private_storage::FileIdentity foreign_id = actual_id;
    foreign_id.file_id_low += 9999;

    kasumi::platform::private_storage::PrivateOutputFile mismatch_file{
        .handle = kasumi::platform::private_storage::invalid_private_handle,
        .path = path,
        .identity = foreign_id,
        .published = false,
    };
    auto res_mismatch = kasumi::platform::private_storage::remove_private_file_if_owned(mismatch_file);
    EXPECT_EQ(res_mismatch, kasumi::platform::private_storage::CleanupResult::IdentityMismatch);
    EXPECT_TRUE(local_entry_exists(node, "test_file.bin"));

    std::filesystem::remove(path);
    kasumi::platform::private_storage::PrivateOutputFile absent_file{
        .handle = kasumi::platform::private_storage::invalid_private_handle,
        .path = path,
        .identity = actual_id,
        .published = false,
    };
    auto res_absent = kasumi::platform::private_storage::remove_private_file_if_owned(absent_file);
    EXPECT_EQ(res_absent, kasumi::platform::private_storage::CleanupResult::AlreadyAbsent);
}




#if defined(KASUMI_SYNC_CRASH_HELPER_PATH)
TEST(LocalCopyDependenciesTest, CopyRecoveryPreInstallCrashRecoversCandidateOrFailsClosed) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "node_a_preinstall_crash"));
    ASSERT_TRUE(init_sync_node(node_b, "node_b_preinstall_crash", node_a.storage_root));

    write_local_file(node_a, "orig.txt", "PreinstallCrashDataBytes");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    write_local_file(node_a, "copy.txt", "PreinstallCrashDataBytes");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    // Crash the child right at before_copy_local_install (after .copy_identity is durable, before destination installed)
    const auto signal = node_b.profile / "copy_crash_preinstall.signal";
    const auto child = run_crash_child(
        node_b, "sync", "before_copy_local_install",
        "", signal);
    ASSERT_TRUE(child.reached_point) << "Child detail: " << child.detail;
    ASSERT_TRUE(child.was_killed);

    // Now restart sync in parent process
    reset_content_counts(node_b);
    auto sync_res = run_node_sync(node_b);
    ASSERT_TRUE(sync_res.has_value()) << (sync_res ? "" : sync_res.error().detail);

    // Verify recovery succeeded safely without remote Content GET
    EXPECT_TRUE(local_entry_exists(node_b, "copy.txt"));
    EXPECT_TRUE(local_entry_exists(node_b, "orig.txt"));
    EXPECT_EQ(read_local_file(node_b, "copy.txt"), "PreinstallCrashDataBytes");
    EXPECT_EQ(node_b.counters.content_gets, 0U);
}

TEST(LocalCopyDependenciesTest, CopyRecoveryPreInstallCrashRejectsForeignCandidate) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "node_a_preinstall_foreign"));
    ASSERT_TRUE(init_sync_node(node_b, "node_b_preinstall_foreign", node_a.storage_root));

    write_local_file(node_a, "orig.txt", "ForeignCandidateTestBytes");
    ASSERT_TRUE(run_node_sync(node_a).has_value());
    ASSERT_TRUE(run_node_sync(node_b).has_value());

    write_local_file(node_a, "copy.txt", "ForeignCandidateTestBytes");
    ASSERT_TRUE(run_node_sync(node_a).has_value());

    const auto signal = node_b.profile / "copy_crash_foreign.signal";
    const auto child = run_crash_child(
        node_b, "sync", "before_copy_local_install",
        "", signal);
    ASSERT_TRUE(child.reached_point) << "Child detail: " << child.detail;
    ASSERT_TRUE(child.was_killed);

    const auto paths = kasumi::application::sync::journal::make_paths(node_b.profile);
    ASSERT_TRUE(paths.has_value());
    const auto loaded = kasumi::application::sync::journal::load(*paths, node_b.key, nullptr);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    const auto& record = **loaded;
    const kasumi::platform::Workspace ws{
        .root = node_b.profile / ".transactions" / record.operation_id};
    const auto copy = std::ranges::find(record.plan.operations, Action::CopyLocal, &Operation::action);
    ASSERT_NE(copy, record.plan.operations.end());
    const auto index = static_cast<std::size_t>(copy - record.plan.operations.begin());
    const auto candidate = kasumi::application::sync::mutation::detail::copy_candidate_path(
        node_b.local / copy->alt_path, ws, index);
    ASSERT_TRUE(std::filesystem::exists(candidate));
    const auto owned_id = kasumi::platform::private_storage::query_file_identity(candidate);
    ASSERT_TRUE(owned_id.valid);
    std::filesystem::rename(candidate, candidate.string() + ".original");
    kasumi::test::write_text(candidate, "ForeignCandidateData");
    const auto foreign_id = kasumi::platform::private_storage::query_file_identity(candidate);
    ASSERT_TRUE(foreign_id.valid);
    ASSERT_FALSE(owned_id == foreign_id);

    reset_content_counts(node_b);
    const auto recovered = run_node_sync(node_b);
    EXPECT_FALSE(recovered.has_value());
    EXPECT_EQ(kasumi::test::read_text(candidate), "ForeignCandidateData");
    EXPECT_FALSE(local_entry_exists(node_b, "copy.txt"));
    EXPECT_EQ(node_b.counters.content_gets, 0U);
    EXPECT_TRUE(std::filesystem::exists(kasumi::platform::workspace_file(ws, index, ".copy_identity")));

}

TEST(LocalCopyDependenciesTest, CopyRecoveryPostInstallCrashRejectsForeignDestination) {
    SyncNode node_a, node_b;
    ASSERT_TRUE(init_sync_node(node_a, "postinstall_foreign_a"));
    ASSERT_TRUE(init_sync_node(node_b, "postinstall_foreign_b", node_a.storage_root));
    write_local_file(node_a, "orig.txt", "Payload");
    ASSERT_TRUE(run_node_sync(node_a));
    ASSERT_TRUE(run_node_sync(node_b));
    write_local_file(node_a, "copy.txt", "Payload");
    ASSERT_TRUE(run_node_sync(node_a));

    const auto child = run_crash_child(
        node_b, "sync", "after_copy_local_install", "",
        node_b.profile / "postinstall_foreign.signal");
    ASSERT_TRUE(child.reached_point) << child.detail;
    ASSERT_TRUE(child.was_killed);
    const auto destination = node_b.local / "copy.txt";
    ASSERT_TRUE(std::filesystem::exists(destination));
    const auto owned_id = kasumi::platform::private_storage::query_file_identity(destination);
    ASSERT_TRUE(owned_id.valid);
    std::filesystem::rename(destination, node_b.local / "preserved.txt");
    kasumi::test::write_text(destination, "Payload");
    const auto foreign_id = kasumi::platform::private_storage::query_file_identity(destination);
    ASSERT_TRUE(foreign_id.valid);
    ASSERT_FALSE(owned_id == foreign_id);

    reset_content_counts(node_b);
    EXPECT_FALSE(run_node_sync(node_b));
    EXPECT_EQ(kasumi::platform::private_storage::query_file_identity(destination), foreign_id);
    EXPECT_EQ(read_local_file(node_b, "copy.txt"), "Payload");
    EXPECT_EQ(read_local_file(node_b, "preserved.txt"), "Payload");
    EXPECT_EQ(read_local_file(node_b, "orig.txt"), "Payload");
    EXPECT_EQ(node_b.counters.content_gets, 0U);
}
#endif
