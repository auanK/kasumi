#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "application/use_cases/context.hpp"
#include "core/hasher.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "runtime/vault.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
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
}

namespace {

using kasumi::transport::Transport;

struct CountingStorageState {
    Transport* base = nullptr;
    std::size_t content_puts = 0;
};

void destroy_counting_storage(void*) noexcept {
}

kasumi::transport::Result counting_initialize(void* context) {
    return kasumi::transport::initialize(
        *static_cast<CountingStorageState*>(context)->base);
}

kasumi::transport::Result counting_put(
    void* context,
    const std::filesystem::path& source,
    std::string_view identifier) {
    auto* state = static_cast<CountingStorageState*>(context);
    if (identifier.find('/') == std::string_view::npos) {
        ++state->content_puts;
    }
    return kasumi::transport::put(*state->base, source, identifier);
}

kasumi::transport::Result counting_get(
    void* context,
    std::string_view identifier,
    const std::filesystem::path& destination) {
    return kasumi::transport::get(
        *static_cast<CountingStorageState*>(context)->base,
        identifier,
        destination);
}

kasumi::transport::PresenceResult counting_presence(
    void* context,
    std::string_view identifier) {
    return kasumi::transport::presence(
        *static_cast<CountingStorageState*>(context)->base, identifier);
}

kasumi::transport::ListingResult counting_list(void* context) {
    return kasumi::transport::list(
        *static_cast<CountingStorageState*>(context)->base);
}

kasumi::transport::ListingResult counting_list_prefix(
    void* context,
    std::string_view prefix) {
    return kasumi::transport::list(
        *static_cast<CountingStorageState*>(context)->base, prefix);
}

kasumi::transport::RemovalResult counting_remove(
    void* context,
    std::string_view identifier) {
    return kasumi::transport::remove(
        *static_cast<CountingStorageState*>(context)->base, identifier);
}

Transport make_counting_storage(CountingStorageState& state) {
    return Transport{
        .state = kasumi::transport::TransportStateHandle{
            &state, destroy_counting_storage},
        .storage = kasumi::transport::StorageOperations{
            .initialize = counting_initialize,
            .put = counting_put,
            .get = counting_get,
            .presence = counting_presence,
            .list = counting_list,
            .list_prefix = counting_list_prefix,
            .remove = counting_remove,
        },
    };
}

class CrashFixture {
public:
    CrashFixture()
        : workspace_(kasumi::test::make_temp_workspace("sync-gc-crash")),
          profile_(kasumi::test::workspace_path(workspace_, "profile")),
          local_(kasumi::test::workspace_path(workspace_, "local")),
          storage_root_(kasumi::test::workspace_path(workspace_, "storage")),
          database_(profile_ / "state.db"), key_(test_key()) {
        std::error_code error;
        std::filesystem::create_directories(profile_, error);
        valid_ = !error;
        std::filesystem::create_directories(local_, error);
        valid_ = valid_ && !error;
        std::filesystem::create_directories(storage_root_, error);
        valid_ = valid_ && !error &&
                 kasumi::state_storage::initialize(database_);
        auto opened = kasumi::transport::open_transport(
            kasumi::platform::path::to_utf8(storage_root_));
        if (!opened) {
            valid_ = false;
            return;
        }
        raw_storage_ = std::move(*opened);
        valid_ = valid_ &&
                 kasumi::transport::initialize(raw_storage_).has_value();
        counting_state_.base = &raw_storage_;
        runtime_ = kasumi::runtime::RuntimeData{
            .local_dir = local_,
            .database_path = database_,
            .key_path = profile_ / "key.bin",
            .storage_location =
                kasumi::platform::path::to_utf8(storage_root_),
        };
        context_ = kasumi::application::detail::OperationContext{
            .operation = kasumi::application::Operation::Sync,
            .runtime = runtime_,
            .summary = {.local_dir = local_,
                        .remote_dir = runtime_.storage_location},
            .key = key_,
            .storage = make_counting_storage(counting_state_),
        };
    }

    bool valid() const noexcept { return valid_; }

    void write(std::string_view relative, std::string_view contents) {
        const auto path = local_ / kasumi::platform::path::from_utf8(relative);
        std::filesystem::create_directories(path.parent_path());
        kasumi::test::write_text(path, contents);
    }

    std::expected<kasumi::application::Response,
                  kasumi::application::Error>
    sync() {
        return kasumi::application::detail::run_sync(context_);
    }

    std::expected<kasumi::application::integrity::GarbageCollectResult,
                  kasumi::application::integrity::Error>
    collect() {
        return kasumi::application::integrity::garbage_collect(
            runtime_, context_.storage, key_);
    }

    std::expected<kasumi::application::integrity::FsckResult,
                  kasumi::application::integrity::Error>
    fsck() {
        return kasumi::application::integrity::fsck(
            runtime_, context_.storage, key_);
    }

    std::expected<std::optional<kasumi::state_storage::StoredState>,
                  std::string>
    state() const {
        return kasumi::state_storage::load_state(database_);
    }

    std::string content_id(std::string_view contents) const {
        return kasumi::crypto::content_identifier(
            key_, kasumi::hasher::hash_string(contents));
    }

    std::optional<std::string> add_orphan(std::string_view contents,
                                          std::string_view name) {
        const auto root = profile_ / "crash-fixtures";
        std::error_code error;
        std::filesystem::create_directories(root, error);
        if (error) {
            return std::nullopt;
        }
        const auto source = root / kasumi::platform::path::from_utf8(
                                        std::string{name} + ".plain");
        const auto encrypted = root / kasumi::platform::path::from_utf8(
                                           std::string{name} + ".enc");
        kasumi::test::write_text(source, contents);
        const auto result = kasumi::crypto::encrypt_file_with_hashes(
            source, encrypted, key_);
        if (!result) {
            return std::nullopt;
        }
        const auto identifier = kasumi::crypto::content_identifier(
            key_, result->plaintext_hash);
        if (!kasumi::transport::put(raw_storage_, encrypted, identifier)) {
            return std::nullopt;
        }
        return identifier;
    }

    kasumi::transport::PresenceResult presence(std::string_view identifier) {
        return kasumi::transport::presence(raw_storage_, identifier);
    }

    kasumi::transport::ListingResult listing() {
        return kasumi::transport::list(raw_storage_);
    }

    std::expected<std::vector<std::string>, std::string> active_writers() {
        auto objects = listing();
        if (!objects) {
            return std::unexpected(objects.error().message);
        }
        const auto layout =
            kasumi::application::history_storage::derive_remote_layout(key_);
        std::vector<std::string> writers;
        for (const auto& object : *objects) {
            if (object.starts_with(layout.writers_prefix)) {
                writers.push_back(object);
            }
        }
        return writers;
    }

    bool remove_abandoned_barrier() {
        const auto layout =
            kasumi::application::history_storage::derive_remote_layout(key_);
        auto writers = active_writers();
        if (!writers || !writers->empty()) {
            return false;
        }
        auto removed = kasumi::transport::remove(
            raw_storage_, layout.barrier_identifier);
        if (!removed) {
            return false;
        }
        auto after = presence(layout.barrier_identifier);
        return after && *after == kasumi::transport::Presence::Absent;
    }

    const std::filesystem::path& profile() const noexcept { return profile_; }
    const std::filesystem::path& local() const noexcept { return local_; }
    const std::filesystem::path& storage_root() const noexcept {
        return storage_root_;
    }
    const std::filesystem::path& database() const noexcept { return database_; }
    const kasumi::runtime::RuntimeData& runtime() const noexcept {
        return runtime_;
    }
    const kasumi::runtime::vault::KeyBytes& key() const noexcept {
        return key_;
    }
    Transport& storage() noexcept { return raw_storage_; }
    std::size_t content_puts() const noexcept {
        return counting_state_.content_puts;
    }
    void reset_content_puts() noexcept { counting_state_.content_puts = 0; }

private:
    kasumi::test::TempWorkspace workspace_;
    std::filesystem::path profile_;
    std::filesystem::path local_;
    std::filesystem::path storage_root_;
    std::filesystem::path database_;
    kasumi::runtime::vault::KeyBytes key_{};
    CountingStorageState counting_state_{};
    Transport raw_storage_{};
    kasumi::runtime::RuntimeData runtime_{};
    kasumi::application::detail::OperationContext context_{};
    bool valid_ = false;
};

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

std::optional<std::wstring> environment_value(const wchar_t* name) {
    const DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
    if (required == 0) {
        if (GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
            return std::nullopt;
        }
        return std::wstring{};
    }
    std::wstring value(required, L'\0');
    const DWORD written = GetEnvironmentVariableW(
        name, value.data(), static_cast<DWORD>(value.size()));
    if (written >= value.size()) {
        return std::nullopt;
    }
    value.resize(written);
    return value;
}

class ScopedEnvironment {
public:
    bool set(const wchar_t* name, std::wstring value) {
        previous_.emplace_back(name, environment_value(name));
        return SetEnvironmentVariableW(name, value.c_str()) != 0;
    }

    ~ScopedEnvironment() {
        for (auto it = previous_.rbegin(); it != previous_.rend(); ++it) {
            SetEnvironmentVariableW(it->first.c_str(),
                                    it->second ? it->second->c_str() : nullptr);
        }
    }

private:
    std::vector<std::pair<std::wstring, std::optional<std::wstring>>> previous_;
};

ChildRun run_child(const CrashFixture& fixture,
                   std::string_view mode,
                   std::string_view point,
                   std::string_view subject,
                   const std::filesystem::path& signal_path) {
    ChildRun result;
    ScopedEnvironment environment;
    const auto ascii = [](std::string_view value) {
        return std::wstring(value.begin(), value.end());
    };
    const auto set = [&](const wchar_t* name, std::wstring value) {
        return environment.set(name, std::move(value));
    };
    if (!set(L"KASUMI_CRASH_TEST_MODE", ascii(mode)) ||
        !set(L"KASUMI_CRASH_TEST_PROFILE", fixture.profile().native()) ||
        !set(L"KASUMI_CRASH_TEST_LOCAL", fixture.local().native()) ||
        !set(L"KASUMI_CRASH_TEST_STORAGE", fixture.storage_root().native()) ||
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
        result.detail = "CreateProcessW failed: " +
                        std::to_string(GetLastError());
        return result;
    }
    CloseHandle(process.hThread);

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds{30};
    while (std::chrono::steady_clock::now() < deadline) {
        if (std::filesystem::exists(signal_path)) {
            result.reached_point = true;
            break;
        }
        const DWORD state = WaitForSingleObject(process.hProcess, 0);
        if (state == WAIT_OBJECT_0) {
            DWORD exit_code = 0;
            GetExitCodeProcess(process.hProcess, &exit_code);
            result.detail = "child exited before the requested point with code " +
                            std::to_string(exit_code);
            CloseHandle(process.hProcess);
            return result;
        }
        Sleep(5);
    }

    if (!result.reached_point) {
        result.detail = "timed out waiting for child crash point";
    } else {
        std::ifstream signal{signal_path, std::ios::binary};
        result.signal_contents.assign(
            std::istreambuf_iterator<char>{signal},
            std::istreambuf_iterator<char>{});
    }
    if (TerminateProcess(process.hProcess, 137) &&
        WaitForSingleObject(process.hProcess, 5000) == WAIT_OBJECT_0) {
        DWORD exit_code = 0;
        result.was_killed = GetExitCodeProcess(process.hProcess, &exit_code) &&
                            exit_code == 137;
    }
    if (!result.was_killed && result.detail.empty()) {
        result.detail = "could not forcibly terminate the child process";
    }
    CloseHandle(process.hProcess);
    return result;
}

#else

ChildRun run_child(const CrashFixture& fixture,
                   std::string_view mode,
                   std::string_view point,
                   std::string_view subject,
                   const std::filesystem::path& signal_path) {
    ChildRun result;
    const std::map<std::string, std::string> overrides{
        {"KASUMI_CRASH_TEST_MODE", std::string{mode}},
        {"KASUMI_CRASH_TEST_PROFILE",
         kasumi::platform::path::to_utf8(fixture.profile())},
        {"KASUMI_CRASH_TEST_LOCAL",
         kasumi::platform::path::to_utf8(fixture.local())},
        {"KASUMI_CRASH_TEST_STORAGE",
         kasumi::platform::path::to_utf8(fixture.storage_root())},
        {"KASUMI_CRASH_TEST_POINT", std::string{point}},
        {"KASUMI_CRASH_TEST_SUBJECT", std::string{subject}},
        {"KASUMI_CRASH_TEST_SIGNAL",
         kasumi::platform::path::to_utf8(signal_path)},
    };
    std::vector<std::string> environment;
    for (char** entry = environ; entry != nullptr && *entry != nullptr;
         ++entry) {
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
    std::array<char*, 2> arguments{
        const_cast<char*>(executable.c_str()), nullptr};
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

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds{30};
    int child_status = 0;
    bool child_reaped = false;
    while (std::chrono::steady_clock::now() < deadline) {
        if (std::filesystem::exists(signal_path)) {
            result.reached_point = true;
            break;
        }
        const auto waited = waitpid(child, &child_status, WNOHANG);
        if (waited == child) {
            child_reaped = true;
            const int exit_code = WIFEXITED(child_status)
                                      ? WEXITSTATUS(child_status)
                                      : -1;
            result.detail =
                "child exited before the requested point with code " +
                std::to_string(exit_code);
            return result;
        }
        if (waited < 0 && errno != EINTR) {
            result.detail = "waitpid failed: " + std::to_string(errno);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }

    if (!result.reached_point && result.detail.empty()) {
        result.detail = "timed out waiting for child crash point";
    } else if (result.reached_point) {
        std::ifstream signal{signal_path, std::ios::binary};
        result.signal_contents.assign(
            std::istreambuf_iterator<char>{signal},
            std::istreambuf_iterator<char>{});
    }

    if (!child_reaped) {
        if (kill(child, SIGKILL) == 0 || errno == ESRCH) {
            while (waitpid(child, &child_status, 0) < 0 && errno == EINTR) {
            }
            result.was_killed = WIFSIGNALED(child_status) &&
                                WTERMSIG(child_status) == SIGKILL;
        }
    }
    if (!result.was_killed && result.detail.empty()) {
        result.detail = "child was not reaped after SIGKILL";
    }
    return result;
}

#endif

testing::AssertionResult expect_crash_point(const ChildRun& child,
                                            std::string_view point,
                                            std::string_view subject) {
    if (!child.reached_point) {
        return testing::AssertionFailure() << child.detail;
    }
    if (!child.was_killed) {
        return testing::AssertionFailure() << child.detail;
    }
    const auto expected =
        std::string{point} + "\n" + std::string{subject} + "\n";
    if (child.signal_contents != expected) {
        return testing::AssertionFailure()
               << "child signaled '" << child.signal_contents
               << "', expected '" << expected << "'";
    }
    return testing::AssertionSuccess();
}

TEST(SyncGcCrashTest, KilledAfterRepairPutBeforeCheckpointRecoversSafely) {
    CrashFixture fixture;
    ASSERT_TRUE(fixture.valid());
    fixture.write("repair.txt", "crash repair content");
    ASSERT_TRUE(fixture.sync().has_value());
    auto before = fixture.state();
    ASSERT_TRUE(before.has_value() && *before);
    const auto content_id = fixture.content_id("crash repair content");
    auto removed = kasumi::transport::remove(fixture.storage(), content_id);
    ASSERT_TRUE(removed.has_value());
    ASSERT_EQ(*removed, kasumi::transport::Removal::Removed);
    ASSERT_TRUE(std::filesystem::exists(fixture.local() / "repair.txt"));
    fixture.write("repair-copy.txt", "crash repair content");
    fixture.reset_content_puts();

    const auto signal = fixture.profile() / "crash-r01.signal";
    const auto child = run_child(fixture,
                                 "sync",
                                 "transport.put",
                                 content_id,
                                 signal);
    ASSERT_TRUE(expect_crash_point(child, "transport.put", content_id));
    ASSERT_TRUE(fixture.presence(content_id).has_value());
    EXPECT_EQ(*fixture.presence(content_id),
              kasumi::transport::Presence::Present);
    auto interrupted = fixture.state();
    ASSERT_TRUE(interrupted.has_value() && *interrupted);
    EXPECT_EQ((*interrupted)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*interrupted)->ciphertext_id, (*before)->ciphertext_id);
    EXPECT_EQ((*interrupted)->tree, (*before)->tree);
    const auto transactions = fixture.profile() / ".transactions";
    ASSERT_TRUE(std::filesystem::is_directory(transactions));
    EXPECT_NE(std::filesystem::directory_iterator{transactions},
              std::filesystem::directory_iterator{});

    fixture.reset_content_puts();
    const auto recovered = fixture.sync();
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&recovered->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_TRUE(summary->published);
    EXPECT_FALSE(summary->partial);
    EXPECT_EQ(fixture.content_puts(), 0U);
    auto after = fixture.state();
    ASSERT_TRUE(after.has_value() && *after);
    EXPECT_NE((*after)->commit_id, (*before)->commit_id);
    EXPECT_NE((*after)->ciphertext_id, (*before)->ciphertext_id);
    EXPECT_NE((*after)->tree, (*before)->tree);
    ASSERT_TRUE(std::filesystem::is_regular_file(fixture.local() / "repair.txt"));
    ASSERT_TRUE(
        std::filesystem::is_regular_file(fixture.local() / "repair-copy.txt"));
    auto audited = fixture.fsck();
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;
}

TEST(SyncGcCrashTest, KilledAfterBarrierAcquisitionFailsClosedOnRestart) {
    CrashFixture fixture;
    ASSERT_TRUE(fixture.valid());
    fixture.write("protected.txt", "protected history");
    ASSERT_TRUE(fixture.sync().has_value());
    const auto before = fixture.state();
    ASSERT_TRUE(before.has_value() && *before);
    const auto orphan = fixture.add_orphan("orphan for abandoned barrier",
                                           "barrier-orphan");
    ASSERT_TRUE(orphan.has_value());
    auto orphan_before = fixture.presence(*orphan);
    ASSERT_TRUE(orphan_before.has_value());
    ASSERT_EQ(*orphan_before, kasumi::transport::Presence::Present);
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(fixture.key());

    const auto child = run_child(fixture,
                                 "gc",
                                 "gc.barrier.acquired",
                                 layout.barrier_identifier,
                                 fixture.profile() / "crash-r02.signal");
    ASSERT_TRUE(expect_crash_point(child,
                                   "gc.barrier.acquired",
                                   layout.barrier_identifier));
    auto barrier = fixture.presence(layout.barrier_identifier);
    ASSERT_TRUE(barrier.has_value());
    EXPECT_EQ(*barrier, kasumi::transport::Presence::Present);
    auto orphan_after = fixture.presence(*orphan);
    ASSERT_TRUE(orphan_after.has_value());
    EXPECT_EQ(*orphan_after, kasumi::transport::Presence::Present);
    auto writers = fixture.active_writers();
    ASSERT_TRUE(writers.has_value());
    EXPECT_TRUE(writers->empty());

    const auto blocked_gc = fixture.collect();
    ASSERT_FALSE(blocked_gc.has_value());
    EXPECT_NE(blocked_gc.error().detail.find("another maintenance barrier"),
              std::string::npos);
    fixture.write("protected.txt", "attempted write under abandoned barrier");
    fixture.reset_content_puts();
    const auto blocked_sync = fixture.sync();
    ASSERT_FALSE(blocked_sync.has_value());
    EXPECT_EQ(fixture.content_puts(), 0U);
    auto unchanged = fixture.state();
    ASSERT_TRUE(unchanged.has_value() && *unchanged);
    EXPECT_EQ((*unchanged)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*unchanged)->tree, (*before)->tree);
    writers = fixture.active_writers();
    ASSERT_TRUE(writers.has_value());
    EXPECT_TRUE(writers->empty());
    ASSERT_TRUE(fixture.remove_abandoned_barrier());
    auto audited = fixture.fsck();
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;
}

TEST(SyncGcCrashTest,
     KilledAfterCandidateRemovalBeforeConfirmationRequiresFreshAnalysis) {
    CrashFixture fixture;
    ASSERT_TRUE(fixture.valid());
    fixture.write("protected.txt", "protected history");
    ASSERT_TRUE(fixture.sync().has_value());
    const auto before = fixture.state();
    ASSERT_TRUE(before.has_value() && *before);
    const auto first = fixture.add_orphan("first orphan", "remove-orphan-a");
    const auto second = fixture.add_orphan("second orphan", "remove-orphan-b");
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    const auto first_candidate = std::min(*first, *second);
    const auto second_candidate = std::max(*first, *second);
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(fixture.key());

    const auto child = run_child(fixture,
                                 "gc",
                                 "transport.remove",
                                 first_candidate,
                                 fixture.profile() / "crash-r03.signal");
    ASSERT_TRUE(expect_crash_point(child, "transport.remove", first_candidate));
    auto first_after = fixture.presence(first_candidate);
    auto second_after = fixture.presence(second_candidate);
    auto barrier = fixture.presence(layout.barrier_identifier);
    ASSERT_TRUE(first_after.has_value());
    ASSERT_TRUE(second_after.has_value());
    ASSERT_TRUE(barrier.has_value());
    EXPECT_EQ(*first_after, kasumi::transport::Presence::Absent);
    EXPECT_EQ(*second_after, kasumi::transport::Presence::Present);
    EXPECT_EQ(*barrier, kasumi::transport::Presence::Present);
    auto writers = fixture.active_writers();
    ASSERT_TRUE(writers.has_value());
    EXPECT_TRUE(writers->empty());

    const auto blocked = fixture.collect();
    ASSERT_FALSE(blocked.has_value());
    EXPECT_NE(blocked.error().detail.find("another maintenance barrier"),
              std::string::npos);
    second_after = fixture.presence(second_candidate);
    ASSERT_TRUE(second_after.has_value());
    EXPECT_EQ(*second_after, kasumi::transport::Presence::Present);

    ASSERT_TRUE(fixture.remove_abandoned_barrier());
    const auto fresh = fixture.collect();
    ASSERT_TRUE(fresh.has_value()) << fresh.error().detail;
    EXPECT_EQ(fresh->candidate_objects, 1U);
    EXPECT_EQ(fresh->removed_objects, 1U);
    first_after = fixture.presence(first_candidate);
    second_after = fixture.presence(second_candidate);
    ASSERT_TRUE(first_after.has_value());
    ASSERT_TRUE(second_after.has_value());
    EXPECT_EQ(*first_after, kasumi::transport::Presence::Absent);
    EXPECT_EQ(*second_after, kasumi::transport::Presence::Absent);
    auto after = fixture.state();
    ASSERT_TRUE(after.has_value() && *after);
    EXPECT_EQ((*after)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*after)->tree, (*before)->tree);
    auto audited = fixture.fsck();
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;
}

} // namespace
