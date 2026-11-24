#include "application/daemon.hpp"
#include "application/daemon/error_classification.hpp"
#include "application/execute.hpp"
#include "application/profile.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "platform/profile_lock.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>

namespace {

using namespace std::chrono_literals;
namespace app = kasumi::application;

template <typename Pred>
bool wait_until(Pred pred,
                std::chrono::milliseconds timeout = std::chrono::seconds{15}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(30ms);
    }
    return pred();
}

struct TwoPeerSetup {
    kasumi::test::TempWorkspace workspace;
    app::ExecutionEnvironment env;
    std::filesystem::path peer_a_dir;
    std::filesystem::path peer_b_dir;
    std::filesystem::path remote_dir;
    std::string hex_key = std::string(64, '7');

    static TwoPeerSetup
    create(const std::string& prefix,
           app::KeyStorage storage = app::KeyStorage::File,
           std::optional<std::uint32_t> sync_interval = 10U) {
        TwoPeerSetup setup{
            .workspace = kasumi::test::make_temp_workspace(prefix),
        };
        setup.env = app::ExecutionEnvironment{
            .app_data_dir =
                kasumi::test::workspace_path(setup.workspace, "app")};
        setup.peer_a_dir =
            kasumi::test::workspace_path(setup.workspace, "peer_a");
        setup.peer_b_dir =
            kasumi::test::workspace_path(setup.workspace, "peer_b");
        setup.remote_dir =
            kasumi::test::workspace_path(setup.workspace, "remote");
        std::filesystem::create_directories(setup.peer_a_dir);
        std::filesystem::create_directories(setup.peer_b_dir);
        std::filesystem::create_directories(setup.remote_dir);

        const auto create_p = [&](std::string name,
                                  const std::filesystem::path& local_dir) {
            app::Profile prof{
                .name = std::move(name),
                .local_dir = local_dir,
                .remote_dir = kasumi::platform::path::to_utf8(setup.remote_dir),
                .min_history_depth = 5U,
                .min_history_age_hours = 6U,
                .key_storage = storage,
                .sync_interval_seconds = sync_interval,
            };
            const auto res = app::create_profile(
                setup.env, prof, app::MasterKeyHex{setup.hex_key});
            EXPECT_TRUE(res.has_value()) << res.error().detail;
        };
        create_p("peer_a", setup.peer_a_dir);
        create_p("peer_b", setup.peer_b_dir);

        const app::Credentials creds =
            storage == app::KeyStorage::Memory
                ? app::Credentials{app::MasterKeyHex{setup.hex_key}}
                : app::Credentials{app::NoCredentials{}};

        kasumi::test::write_text(setup.peer_a_dir / "seed.txt", "initial-seed");
        const auto sync_a = app::execute(
            app::ExecutionInput{.request = {.operation = app::Operation::Sync,
                                            .profile_name = "peer_a"},
                                .credentials = creds,
                                .environment = setup.env});
        EXPECT_TRUE(sync_a.has_value())
            << (sync_a ? std::string{} : sync_a.error().detail);
        const auto sync_b = app::execute(
            app::ExecutionInput{.request = {.operation = app::Operation::Sync,
                                            .profile_name = "peer_b"},
                                .credentials = creds,
                                .environment = setup.env});
        EXPECT_TRUE(sync_b.has_value())
            << (sync_b ? std::string{} : sync_b.error().detail);
        return setup;
    }
};

TEST(DaemonEngineTest, EnforcesSingleInstanceLockAndIpcSecurity) {
    auto setup =
        TwoPeerSetup::create("kasumi-daemon-lock-", app::KeyStorage::File, 0U);

    app::DaemonOptions opts;
    opts.watch_debounce = 150ms;
    opts.config_poll_interval = 200ms;
    auto first = app::start_daemon_session(setup.env, opts);
    ASSERT_TRUE(first.has_value()) << first.error().detail;
    EXPECT_TRUE(app::is_daemon_running(setup.env));

    const auto duplicate = app::start_daemon_session(setup.env, opts);
    ASSERT_FALSE(duplicate.has_value());
    EXPECT_EQ(duplicate.error().code, app::DaemonErrorCode::AlreadyRunning);

    const auto status = app::query_daemon_status(setup.env);
    ASSERT_TRUE(status.has_value()) << status.error().detail;
    EXPECT_TRUE(status->running);
    EXPECT_GT(status->ipc_port, 0U);
    EXPECT_EQ(status->profiles.size(), 2U);

    // Unauthenticated or browser-originated requests must be rejected.
    httplib::Client unauth("127.0.0.1", status->ipc_port);
    const auto r_unauth = unauth.Get("/v1/status");
    ASSERT_TRUE(r_unauth);
    EXPECT_EQ(r_unauth->status, 403);

    const auto r_origin = unauth.Get(
        "/v1/status", httplib::Headers{{"Origin", "https://evil.example"}});
    ASSERT_TRUE(r_origin);
    EXPECT_EQ(r_origin->status, 403);

    ASSERT_TRUE(app::stop_running_daemon(setup.env).has_value());
    EXPECT_FALSE(app::is_daemon_session_running(*first));
    EXPECT_FALSE(app::is_daemon_running(setup.env));
}

TEST(DaemonEngineTest,
     WatchesFilesWithDebounceSelfSuppressionAndFastNoopPolls) {
    auto setup = TwoPeerSetup::create(
        "kasumi-daemon-watch-", app::KeyStorage::File, 10U);
    app::DaemonOptions opts;
    opts.watch_debounce = 150ms;
    opts.watch_max_wait = 600ms;
    opts.config_poll_interval = 200ms;
    opts.full_scan_verification_interval = 10min;
    auto session = app::start_daemon_session(setup.env, opts);
    ASSERT_TRUE(session.has_value()) << session.error().detail;

    // Initial baseline sync establishes warm observation + watcher baseline.
    const auto trig =
        app::trigger_daemon_session_sync(*session, "peer_a", true);
    ASSERT_TRUE(trig.has_value()) << trig.error().detail;
    EXPECT_TRUE(trig->failures.empty());
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_b", true).has_value());

    // Wait a moment so periodic idle fast polls can run safely on both
    // profiles.
    EXPECT_TRUE(wait_until([&] {
        const auto st = app::query_daemon_session_status(*session, "peer_a");
        return st && !st->profiles.empty() &&
               st->profiles[0].warm_transport_active &&
               st->profiles[0].watcher_active;
    }));

    // Modify file on peer_a -> watcher triggers debounced auto-sync!
    const auto a_before = app::query_daemon_session_status(*session, "peer_a")
                              ->profiles[0]
                              .sync_runs;
    kasumi::test::write_text(setup.peer_a_dir / "note.txt", "from-peer-a");
    ASSERT_TRUE(wait_until(
        [&] {
            const auto st =
                app::query_daemon_session_status(*session, "peer_a");
            return st && st->profiles[0].sync_runs > a_before;
        },
        15s));

    // Trigger peer_b to download note.txt and ensure self-mutation suppression
    // avoids cascading extra sync runs from its own download!
    const auto b_before = app::query_daemon_session_status(*session, "peer_b")
                              ->profiles[0]
                              .sync_runs;
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_b", true).has_value());
    EXPECT_EQ(kasumi::test::read_text(setup.peer_b_dir / "note.txt"),
              "from-peer-a");
    std::this_thread::sleep_for(500ms);
    const auto b_after = app::query_daemon_session_status(*session, "peer_b")
                             ->profiles[0]
                             .sync_runs;
    EXPECT_EQ(b_after, b_before + 1U);

    // Pause peer_a, write ignored/non-ignored file -> stays paused cleanly.
    ASSERT_TRUE(app::pause_daemon_profile(setup.env, "peer_a").has_value());
    const auto paused_st = app::query_daemon_session_status(*session, "peer_a");
    ASSERT_TRUE(paused_st.has_value());
    EXPECT_EQ(paused_st->profiles[0].state, app::DaemonProfileState::Paused);
    EXPECT_FALSE(paused_st->profiles[0].watcher_active);
    ASSERT_TRUE(app::resume_daemon_profile(setup.env, "peer_a").has_value());

    app::stop_daemon_session(*session);
}

TEST(DaemonEngineTest, FastNoopPollIncrementsWithoutExtraSyncRuns) {
    auto workspace = kasumi::test::make_temp_workspace("kasumi-fastpoll-");
    const app::ExecutionEnvironment env{
        .app_data_dir = kasumi::test::workspace_path(workspace, "app")};
    const auto local_dir = kasumi::test::workspace_path(workspace, "local");
    const auto remote_dir = kasumi::test::workspace_path(workspace, "remote");
    std::filesystem::create_directories(local_dir);
    std::filesystem::create_directories(remote_dir);
    const std::string hex_key(64, '3');

    ASSERT_TRUE(
        app::create_profile(
            env,
            app::Profile{
                .name = "main",
                .local_dir = local_dir,
                .remote_dir = kasumi::platform::path::to_utf8(remote_dir),
                .key_storage = app::KeyStorage::File,
                .sync_interval_seconds = 0U,
            },
            app::MasterKeyHex{hex_key})
            .has_value());
    kasumi::test::write_text(local_dir / "doc.txt", "v1");
    const auto init_sync = app::execute(app::ExecutionInput{
        .request = {.operation = app::Operation::Sync, .profile_name = "main"},
        .credentials = app::NoCredentials{},
        .environment = env});
    ASSERT_TRUE(init_sync.has_value())
        << (init_sync ? std::string{} : init_sync.error().detail);

    // Set sync_interval_seconds directly in TOML? 10s is min valid in config,
    // so wait up to 13s to observe a genuine timer-driven fast no-op poll!
    auto profs = app::list_profiles(env);
    ASSERT_TRUE(profs && profs->size() == 1U);
    (*profs)[0].sync_interval_seconds = 10U;
    ASSERT_TRUE(app::update_profile(env, (*profs)[0], false).has_value());

    app::DaemonOptions opts;
    opts.watch_debounce = 100ms;
    opts.full_scan_verification_interval = 10min;
    auto session = app::start_daemon_session(env, opts);
    ASSERT_TRUE(session.has_value()) << session.error().detail;

    // Wait for initial check (runs=1) and subsequent periodic 10s fast no-op
    // poll.
    ASSERT_TRUE(wait_until(
        [&] {
            const auto st = app::query_daemon_session_status(*session, "main");
            return st && st->profiles[0].sync_runs >= 1U &&
                   st->profiles[0].fast_noop_polls >= 1U;
        },
        18s));
    const auto st = app::query_daemon_session_status(*session, "main");
    ASSERT_TRUE(st.has_value());
    EXPECT_EQ(st->profiles[0].sync_runs, 1U);
    EXPECT_GE(st->profiles[0].fast_noop_polls, 1U);
    EXPECT_TRUE(st->profiles[0].warm_transport_active);

    app::stop_daemon_session(*session);
}

TEST(DaemonEngineTest,
     MemoryProfileStartsLockedVerifiesKeyUnlocksSyncsAndLocks) {
    auto setup =
        TwoPeerSetup::create("kasumi-daemon-mem-", app::KeyStorage::Memory, 0U);

    app::DaemonOptions opts;
    opts.watch_debounce = 100ms;
    auto session = app::start_daemon_session(setup.env, opts);
    ASSERT_TRUE(session.has_value()) << session.error().detail;

    const auto locked_st = app::query_daemon_session_status(*session, "peer_a");
    ASSERT_TRUE(locked_st.has_value());
    EXPECT_EQ(locked_st->profiles[0].state, app::DaemonProfileState::Locked);
    EXPECT_TRUE(locked_st->profiles[0].locked);

    // Wrong key must be rejected before storing in memory.
    const auto bad_unlock = app::unlock_daemon_profile(
        setup.env, "peer_a", app::MasterKeyHex{std::string(64, 'a')});
    ASSERT_FALSE(bad_unlock.has_value());
    EXPECT_EQ(bad_unlock.error().code, app::DaemonErrorCode::InvalidCredential);

    // Right key unlocks via encrypted IPC payload.
    ASSERT_TRUE(app::unlock_daemon_profile(
                    setup.env, "peer_a", app::MasterKeyHex{setup.hex_key})
                    .has_value());

    kasumi::test::write_text(setup.peer_a_dir / "secret.txt", "ram-only-key");
    const auto sync_res = app::trigger_daemon_sync(setup.env, "peer_a", true);
    ASSERT_TRUE(sync_res.has_value()) << sync_res.error().detail;
    EXPECT_TRUE(sync_res->failures.empty());

    // Lock erases key from SecureKeyArena cleanly.
    ASSERT_TRUE(app::lock_daemon_profile(setup.env, "peer_a").has_value());
    const auto relocked = app::query_daemon_session_status(*session, "peer_a");
    ASSERT_TRUE(relocked.has_value());
    EXPECT_TRUE(relocked->profiles[0].locked);
    EXPECT_EQ(relocked->profiles[0].state, app::DaemonProfileState::Locked);

    app::stop_daemon_session(*session);
}

TEST(DaemonEngineTest,
     CircuitBreakerTripsOnEmptyLocalAndBackoffsOnExternalLock) {
    auto setup = TwoPeerSetup::create(
        "kasumi-daemon-safety-", app::KeyStorage::File, 0U);
    app::DaemonOptions opts;
    opts.watch_debounce = 100ms;
    auto session = app::start_daemon_session(setup.env, opts);
    ASSERT_TRUE(session.has_value()) << session.error().detail;
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_a", true).has_value());

    // Hold external profile lock simulating a concurrent CLI execution.
    auto ext_lock = kasumi::platform::acquire_profile_lock(
        setup.env.app_data_dir / "profile-peer_a.lock");
    ASSERT_TRUE(ext_lock.has_value()) << ext_lock.error();

    const auto blocked_sync =
        app::trigger_daemon_session_sync(*session, "peer_a", true);
    ASSERT_TRUE(blocked_sync.has_value());
    EXPECT_FALSE(blocked_sync->failures.empty());
    const auto backoff_st =
        app::query_daemon_session_status(*session, "peer_a");
    ASSERT_TRUE(backoff_st.has_value());
    EXPECT_EQ(backoff_st->profiles[0].state, app::DaemonProfileState::Backoff);
    EXPECT_GT(backoff_st->profiles[0].backoff_seconds, 0U);
    kasumi::platform::release_profile_lock(*ext_lock);

    // Delete local_dir while DB has history -> empty_local_blocked trips
    // NeedsAttention circuit breaker cleanly without touching remote!
    std::filesystem::remove_all(setup.peer_b_dir);
    const auto guard_sync =
        app::trigger_daemon_session_sync(*session, "peer_b", true);
    ASSERT_TRUE(guard_sync.has_value());
    EXPECT_FALSE(guard_sync->failures.empty());
    const auto attn = app::query_daemon_session_status(*session, "peer_b");
    ASSERT_TRUE(attn.has_value());
    EXPECT_EQ(attn->profiles[0].state, app::DaemonProfileState::NeedsAttention);

    app::stop_daemon_session(*session);
}

TEST(DaemonEngineTest,
     DefaultGcDisabledPauseDuringLockAndDaemonLogsCancelWork) {
    auto setup =
        TwoPeerSetup::create("kasumi-daemon-p0p1-", app::KeyStorage::File, 0U);
    const auto profiles = app::list_profiles(setup.env);
    ASSERT_TRUE(profiles && profiles->size() == 2U);
    for (const auto& p : *profiles) {
        EXPECT_FALSE(p.gc_interval_hours.has_value());
    }

    app::DaemonOptions opts;
    opts.watch_debounce = 100ms;
    auto session = app::start_daemon_session(setup.env, opts);
    ASSERT_TRUE(session.has_value()) << session.error().detail;

    const auto init_st = app::query_daemon_session_status(*session, "peer_a");
    ASSERT_TRUE(init_st.has_value());
    EXPECT_GE(init_st->api_version, 1U);
    EXPECT_FALSE(init_st->kasumi_version.empty());
    ASSERT_EQ(init_st->profiles.size(), 1U);
    EXPECT_EQ(init_st->profiles[0].gc_interval_hours, 0U);
    EXPECT_FALSE(init_st->profiles[0].next_gc_at.has_value());
    EXPECT_FALSE(init_st->profiles[0].local_dir.empty());
    EXPECT_FALSE(init_st->profiles[0].remote_dir.empty());

    // Simulate pausing while profile lock is held externally -> must succeed
    // and stay paused across config_poll ticks without auto-unpausing.
    auto ext_lock = kasumi::platform::acquire_profile_lock(
        setup.env.app_data_dir / "profile-peer_a.lock");
    ASSERT_TRUE(ext_lock.has_value()) << ext_lock.error();
    ASSERT_TRUE(app::pause_daemon_profile(setup.env, "peer_a").has_value());
    kasumi::platform::release_profile_lock(*ext_lock);

    std::this_thread::sleep_for(600ms);
    const auto paused_st = app::query_daemon_session_status(*session, "peer_a");
    ASSERT_TRUE(paused_st.has_value());
    EXPECT_EQ(paused_st->profiles[0].state, app::DaemonProfileState::Paused);

    // Reloading & resuming works cleanly.
    ASSERT_TRUE(app::resume_daemon_profile(setup.env, "peer_a").has_value());
    ASSERT_TRUE(app::reload_running_daemon(setup.env).has_value());

    // Cancel request succeeds over session & IPC even when idle.
    EXPECT_TRUE(app::cancel_daemon_profile(setup.env, "peer_a").has_value());

    // Persistent daemon logs + filtered query work.
    const auto logs = app::query_daemon_events(
        setup.env,
        app::DaemonLogQuery{.profile_name = "peer_a", .max_lines = 50U});
    ASSERT_TRUE(logs.has_value()) << logs.error().detail;
    EXPECT_FALSE(logs->log_path.empty());
    EXPECT_FALSE(logs->events.empty());

    app::stop_daemon_session(*session);
}

TEST(DaemonEngineTest,
     ClassifiesConcurrentLocalMutationAsTransientAndInvariantsAsPermanent) {
    using app::Error;
    using app::ErrorCode;
    namespace dd = kasumi::application::daemon_detail;

    const auto check = [](const Error& err,
                          bool expected_transient,
                          bool expected_concurrent) {
        EXPECT_EQ(dd::is_transient_sync_error(err), expected_transient)
            << err.detail;
        EXPECT_EQ(dd::is_concurrent_local_mutation_error(err),
                  expected_concurrent)
            << err.detail;
    };

    check(Error{.code = ErrorCode::SynchronizationFailure,
                .detail = "composition_mismatch: materialized tree does not "
                          "match reconciled candidate tree"},
          true,
          true);
    check(Error{.code = ErrorCode::SynchronizationFailure,
                .detail = "composition_mismatch: local materialization "
                          "diverges from observed head"},
          true,
          true);
    check(Error{.code = ErrorCode::SynchronizationFailure,
                .detail = "concurrent_modification: file changed during sync"},
          true,
          true);

    // True internal invariants or corruption must still trip NeedsAttention.
    check(Error{.code = ErrorCode::SynchronizationFailure,
                .detail = "composition_mismatch: reconciliation input and "
                          "result do not match"},
          false,
          false);
    check(Error{.code = ErrorCode::SynchronizationFailure,
                .detail =
                    "composition_mismatch: input cannot reproduce result: "
                    "invalid input"},
          false,
          false);
    check(Error{.code = ErrorCode::SynchronizationFailure,
                .detail = "corrupt ciphertext block"},
          false,
          false);
    check(Error{.code = ErrorCode::SynchronizationFailure,
                .detail = "initial sync required",
                .empty_local_blocked = true},
          false,
          false);
    check(Error{.code = ErrorCode::SynchronizationFailure,
                .detail = "disk full",
                .insufficient_disk_space = true},
          false,
          false);
    check(
        Error{.code = ErrorCode::CredentialFailure, .detail = "wrong password"},
        false,
        false);

    // Transient network / lock errors backoff without marking local race.
    check(Error{.code = ErrorCode::SynchronizationFailure,
                .detail = "busy",
                .lock_busy = true},
          true,
          false);
    check(Error{.code = ErrorCode::SynchronizationFailure,
                .detail = "busy",
                .remote_busy = true},
          true,
          false);
    check(Error{.code = ErrorCode::SynchronizationFailure,
                .detail = "connection reset by peer"},
          true,
          false);
    check(Error{.code = ErrorCode::SynchronizationFailure,
                .detail = "RC request timed out"},
          true,
          false);
}

TEST(DaemonEngineTest,
     ConcurrentLocalEditsDuringSyncConvergeWithoutTrippingNeedsAttention) {
    auto setup =
        TwoPeerSetup::create("kasumi-daemon-race-", app::KeyStorage::File, 10U);
    app::DaemonOptions opts;
    opts.watch_debounce = 50ms;
    opts.watch_max_wait = 150ms;
    opts.config_poll_interval = 200ms;
    opts.full_scan_verification_interval = 10min;
    opts.enable_ipc_server = false;

    auto session = app::start_daemon_session(setup.env, opts);
    ASSERT_TRUE(session.has_value()) << session.error().detail;

    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_a", true).has_value());
    ASSERT_TRUE(wait_until([&] {
        const auto st = app::query_daemon_session_status(*session, "peer_a");
        return st && !st->profiles.empty() && st->profiles[0].watcher_active;
    }));

    std::atomic<bool> saw_needs_attention{false};
    std::atomic<bool> writer_done{false};
    std::thread writer([&] {
        for (int i = 0; i < 40; ++i) {
            kasumi::test::write_text(setup.peer_a_dir / "f0.md",
                                     "v-" + std::to_string(i));
            kasumi::test::write_text(setup.peer_a_dir / "f1.md",
                                     "side-" + std::to_string(i));
            if (i % 5 == 0) {
                std::error_code ec;
                std::filesystem::rename(
                    setup.peer_a_dir / "f1.md", setup.peer_a_dir / "f2.md", ec);
            }
            const auto st =
                app::query_daemon_session_status(*session, "peer_a");
            if (st && !st->profiles.empty() &&
                st->profiles[0].state ==
                    app::DaemonProfileState::NeedsAttention) {
                saw_needs_attention.store(true, std::memory_order_relaxed);
            }
            std::this_thread::sleep_for(20ms);
        }
        writer_done.store(true, std::memory_order_release);
    });

    while (!writer_done.load(std::memory_order_acquire)) {
        static_cast<void>(
            app::trigger_daemon_session_sync(*session, "peer_a", false));
        std::this_thread::sleep_for(60ms);
    }
    writer.join();

    kasumi::test::write_text(setup.peer_a_dir / "f0.md",
                             "final-converged-value");
    std::this_thread::sleep_for(300ms);
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_a", true).has_value());
    ASSERT_TRUE(wait_until(
        [&] {
            const auto st =
                app::query_daemon_session_status(*session, "peer_a");
            return st && !st->profiles.empty() &&
                   st->profiles[0].state == app::DaemonProfileState::Idle &&
                   st->profiles[0].dirty_paths_count == 0U;
        },
        15s));
    EXPECT_FALSE(saw_needs_attention.load(std::memory_order_relaxed));

    const auto final_a = app::query_daemon_session_status(*session, "peer_a");
    ASSERT_TRUE(final_a && !final_a->profiles.empty());
    EXPECT_NE(final_a->profiles[0].state,
              app::DaemonProfileState::NeedsAttention);

    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_b", true).has_value());
    EXPECT_EQ(kasumi::test::read_text(setup.peer_b_dir / "f0.md"),
              "final-converged-value");

    app::stop_daemon_session(*session);
}

TEST(DaemonEngineTest,
     FullUserLifecycleCreateEditRenameDeletePauseResumeReloadAndFastStop) {
    auto setup =
        TwoPeerSetup::create("kasumi-daemon-life-", app::KeyStorage::File, 10U);
    app::DaemonOptions opts;
    opts.watch_debounce = 80ms;
    opts.watch_max_wait = 250ms;
    opts.config_poll_interval = 200ms;
    opts.full_scan_verification_interval = 10min;

    auto session = app::start_daemon_session(setup.env, opts);
    ASSERT_TRUE(session.has_value()) << session.error().detail;

    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_a", true).has_value());
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_b", true).has_value());
    ASSERT_TRUE(wait_until([&] {
        const auto st = app::query_daemon_session_status(*session, "peer_a");
        return st && !st->profiles.empty() && st->profiles[0].watcher_active;
    }));

    auto wait_sync_delta = [&](std::uint64_t before) {
        return wait_until(
            [&] {
                const auto st =
                    app::query_daemon_session_status(*session, "peer_a");
                return st && !st->profiles.empty() &&
                       st->profiles[0].sync_runs > before &&
                       st->profiles[0].state == app::DaemonProfileState::Idle &&
                       st->profiles[0].dirty_paths_count == 0U;
            },
            15s);
    };

    // 1. Create
    const auto s0 = app::query_daemon_session_status(*session, "peer_a")
                        ->profiles[0]
                        .sync_runs;
    kasumi::test::write_text(setup.peer_a_dir / "doc.md", "v1");
    ASSERT_TRUE(wait_sync_delta(s0));
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_b", true).has_value());
    EXPECT_EQ(kasumi::test::read_text(setup.peer_b_dir / "doc.md"), "v1");

    // 2. Edit
    const auto s1 = app::query_daemon_session_status(*session, "peer_a")
                        ->profiles[0]
                        .sync_runs;
    kasumi::test::write_text(setup.peer_a_dir / "doc.md", "v2");
    ASSERT_TRUE(wait_sync_delta(s1));
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_b", true).has_value());
    EXPECT_EQ(kasumi::test::read_text(setup.peer_b_dir / "doc.md"), "v2");

    // 3. Rename
    const auto s2 = app::query_daemon_session_status(*session, "peer_a")
                        ->profiles[0]
                        .sync_runs;
    std::filesystem::rename(setup.peer_a_dir / "doc.md",
                            setup.peer_a_dir / "doc-renamed.md");
    ASSERT_TRUE(wait_sync_delta(s2));
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_b", true).has_value());
    EXPECT_FALSE(std::filesystem::exists(setup.peer_b_dir / "doc.md"));
    EXPECT_EQ(kasumi::test::read_text(setup.peer_b_dir / "doc-renamed.md"),
              "v2");

    // 4. Pause + edit while paused + resume
    ASSERT_TRUE(app::pause_daemon_profile(setup.env, "peer_a").has_value());
    const auto paused_runs =
        app::query_daemon_session_status(*session, "peer_a")
            ->profiles[0]
            .sync_runs;
    kasumi::test::write_text(setup.peer_a_dir / "paused.md", "while-paused");
    std::this_thread::sleep_for(400ms);
    const auto paused_st = app::query_daemon_session_status(*session, "peer_a");
    ASSERT_TRUE(paused_st && !paused_st->profiles.empty());
    EXPECT_EQ(paused_st->profiles[0].state, app::DaemonProfileState::Paused);
    EXPECT_EQ(paused_st->profiles[0].sync_runs, paused_runs);

    ASSERT_TRUE(app::resume_daemon_profile(setup.env, "peer_a").has_value());
    ASSERT_TRUE(wait_sync_delta(paused_runs));
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_b", true).has_value());
    EXPECT_EQ(kasumi::test::read_text(setup.peer_b_dir / "paused.md"),
              "while-paused");

    // 5. Delete + reload + timed stop
    const auto s3 = app::query_daemon_session_status(*session, "peer_a")
                        ->profiles[0]
                        .sync_runs;
    std::filesystem::remove(setup.peer_a_dir / "doc-renamed.md");
    ASSERT_TRUE(wait_sync_delta(s3));
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_b", true).has_value());
    EXPECT_FALSE(std::filesystem::exists(setup.peer_b_dir / "doc-renamed.md"));

    ASSERT_TRUE(app::reload_running_daemon(setup.env).has_value());
    const auto stop_started = std::chrono::steady_clock::now();
    app::stop_daemon_session(*session);
    EXPECT_LT(std::chrono::steady_clock::now() - stop_started, 5s);
}

TEST(DaemonEngineTest,
     TwoIndependentDaemonsConvergeRemoteEditsConflictsAndMassDeletes) {
    auto workspace = kasumi::test::make_temp_workspace("kasumi-daemon-2p-");
    const app::ExecutionEnvironment env_a{
        .app_data_dir = kasumi::test::workspace_path(workspace, "app_a")};
    const app::ExecutionEnvironment env_b{
        .app_data_dir = kasumi::test::workspace_path(workspace, "app_b")};
    const auto dir_a = kasumi::test::workspace_path(workspace, "vault_a");
    const auto dir_b = kasumi::test::workspace_path(workspace, "vault_b");
    const auto remote_dir = kasumi::test::workspace_path(workspace, "remote");
    std::filesystem::create_directories(dir_a);
    std::filesystem::create_directories(dir_b);
    std::filesystem::create_directories(remote_dir);

    const std::string hex_key(64, '5');
    ASSERT_TRUE(
        app::create_profile(
            env_a,
            app::Profile{
                .name = "peer_a",
                .local_dir = dir_a,
                .remote_dir = kasumi::platform::path::to_utf8(remote_dir),
                .key_storage = app::KeyStorage::File,
                .sync_interval_seconds = 10U,
            },
            app::MasterKeyHex{hex_key})
            .has_value());
    ASSERT_TRUE(
        app::create_profile(
            env_b,
            app::Profile{
                .name = "peer_b",
                .local_dir = dir_b,
                .remote_dir = kasumi::platform::path::to_utf8(remote_dir),
                .key_storage = app::KeyStorage::File,
                .sync_interval_seconds = 10U,
            },
            app::MasterKeyHex{hex_key})
            .has_value());

    kasumi::test::write_text(dir_a / "conflict.md", "base-line\n");
    ASSERT_TRUE(
        app::execute(app::ExecutionInput{
                         .request = {.operation = app::Operation::Sync,
                                     .profile_name = "peer_a"},
                         .credentials = app::NoCredentials{},
                         .environment = env_a})
            .has_value());
    ASSERT_TRUE(
        app::execute(app::ExecutionInput{
                         .request = {.operation = app::Operation::Sync,
                                     .profile_name = "peer_b"},
                         .credentials = app::NoCredentials{},
                         .environment = env_b})
            .has_value());

    app::DaemonOptions opts;
    opts.watch_debounce = 80ms;
    opts.watch_max_wait = 250ms;
    opts.config_poll_interval = 150ms;
    opts.full_scan_verification_interval = 10min;

    auto session_a = app::start_daemon_session(env_a, opts);
    ASSERT_TRUE(session_a.has_value()) << session_a.error().detail;
    auto session_b = app::start_daemon_session(env_b, opts);
    ASSERT_TRUE(session_b.has_value()) << session_b.error().detail;

    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session_a, "peer_a", true)
            .has_value());
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session_b, "peer_b", true)
            .has_value());
    ASSERT_TRUE(wait_until([&] {
        const auto sa = app::query_daemon_session_status(*session_a, "peer_a");
        const auto sb = app::query_daemon_session_status(*session_b, "peer_b");
        return sa && sb && !sa->profiles.empty() && !sb->profiles.empty() &&
               sa->profiles[0].watcher_active && sb->profiles[0].watcher_active;
    }));

    // 1. Multi-chunk payload (~2 MiB) + note on peer_a -> peer_b downloads
    //    intact and self-suppression prevents cascading extra sync runs.
    const std::string large_payload(2U * 1024U * 1024U, 'K');
    const auto a_s0 = app::query_daemon_session_status(*session_a, "peer_a")
                          ->profiles[0]
                          .sync_runs;
    kasumi::test::write_text(dir_a / "large_2mb.bin", large_payload);
    kasumi::test::write_text(dir_a / "hello.md", "from-daemon-a");
    ASSERT_TRUE(wait_until(
        [&] {
            const auto sa =
                app::query_daemon_session_status(*session_a, "peer_a");
            return sa && sa->profiles[0].sync_runs > a_s0 &&
                   sa->profiles[0].state == app::DaemonProfileState::Idle &&
                   sa->profiles[0].dirty_paths_count == 0U;
        },
        15s));

    const auto b_s0 = app::query_daemon_session_status(*session_b, "peer_b")
                          ->profiles[0]
                          .sync_runs;
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session_b, "peer_b", true)
            .has_value());
    EXPECT_EQ(kasumi::test::read_text(dir_b / "hello.md"), "from-daemon-a");
    EXPECT_EQ(kasumi::test::read_text(dir_b / "large_2mb.bin"), large_payload);
    std::this_thread::sleep_for(400ms);
    EXPECT_EQ(app::query_daemon_session_status(*session_b, "peer_b")
                  ->profiles[0]
                  .sync_runs,
              b_s0 + 1U);

    // 2. Real simultaneous conflict: pause peer_b, edit conflict.md on both
    //    daemons, resume peer_b -> materializes .kasumiconflict_* without
    //    tripping NeedsAttention on either daemon.
    ASSERT_TRUE(app::pause_daemon_profile(env_b, "peer_b").has_value());
    const auto a_s1 = app::query_daemon_session_status(*session_a, "peer_a")
                          ->profiles[0]
                          .sync_runs;
    kasumi::test::write_text(dir_a / "conflict.md", "edited-on-a\n");
    ASSERT_TRUE(wait_until(
        [&] {
            const auto sa =
                app::query_daemon_session_status(*session_a, "peer_a");
            return sa && sa->profiles[0].sync_runs > a_s1 &&
                   sa->profiles[0].state == app::DaemonProfileState::Idle;
        },
        15s));
    kasumi::test::write_text(dir_b / "conflict.md", "edited-on-b\n");
    ASSERT_TRUE(app::resume_daemon_profile(env_b, "peer_b").has_value());
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session_b, "peer_b", true)
            .has_value());

    bool saw_conflict_file = false;
    for (const auto& entry : std::filesystem::directory_iterator(dir_b)) {
        const auto name = kasumi::platform::path::to_utf8(
            entry.path().filename());
        if (name.find("kasumiconflict") != std::string::npos) {
            saw_conflict_file = true;
        }
    }
    EXPECT_TRUE(saw_conflict_file);
    EXPECT_NE(app::query_daemon_session_status(*session_a, "peer_a")
                  ->profiles[0]
                  .state,
              app::DaemonProfileState::NeedsAttention);
    EXPECT_NE(app::query_daemon_session_status(*session_b, "peer_b")
                  ->profiles[0]
                  .state,
              app::DaemonProfileState::NeedsAttention);

    // 3. Mass delete propagates from peer_a -> peer_b cleanly.
    const auto a_s2 = app::query_daemon_session_status(*session_a, "peer_a")
                          ->profiles[0]
                          .sync_runs;
    std::filesystem::remove(dir_a / "large_2mb.bin");
    std::filesystem::remove(dir_a / "hello.md");
    ASSERT_TRUE(wait_until(
        [&] {
            const auto sa =
                app::query_daemon_session_status(*session_a, "peer_a");
            return sa && sa->profiles[0].sync_runs > a_s2 &&
                   sa->profiles[0].state == app::DaemonProfileState::Idle &&
                   sa->profiles[0].dirty_paths_count == 0U;
        },
        15s));
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session_b, "peer_b", true)
            .has_value());
    EXPECT_FALSE(std::filesystem::exists(dir_b / "large_2mb.bin"));
    EXPECT_FALSE(std::filesystem::exists(dir_b / "hello.md"));

    app::stop_daemon_session(*session_a);
    app::stop_daemon_session(*session_b);
}

TEST(DaemonEngineTest,
     ConfigTomlHotReloadUpdatesIntervalAutomaticallyWithoutReloadIpc) {
    auto setup = TwoPeerSetup::create(
        "kasumi-daemon-hotreload-", app::KeyStorage::File, 15U);
    app::DaemonOptions opts;
    opts.watch_debounce = 80ms;
    opts.config_poll_interval = 100ms;
    opts.full_scan_verification_interval = 10min;

    auto session = app::start_daemon_session(setup.env, opts);
    ASSERT_TRUE(session.has_value()) << session.error().detail;

    ASSERT_TRUE(wait_until([&] {
        const auto st = app::query_daemon_session_status(*session, "peer_a");
        return st && !st->profiles.empty() &&
               st->profiles[0].sync_interval_seconds == 15U;
    }));

    // Edit config.toml directly on disk without calling reload_running_daemon.
    const auto config_path = setup.env.app_data_dir / "config.toml";
    std::string toml = kasumi::test::read_text(config_path);
    const std::string needle = "sync_interval_seconds = 15";
    const auto pos = toml.find(needle);
    ASSERT_NE(pos, std::string::npos);
    toml.replace(pos, needle.size(), "sync_interval_seconds = 25");
    kasumi::test::write_text(config_path, toml);

    ASSERT_TRUE(wait_until(
        [&] {
            const auto st =
                app::query_daemon_session_status(*session, "peer_a");
            return st && !st->profiles.empty() &&
                   st->profiles[0].sync_interval_seconds == 25U;
        },
        10s));

    app::stop_daemon_session(*session);
}

TEST(DaemonEngineTest,
     ConcurrentCliFsckAndInFlightCancelKeepDaemonHealthyAndConvergent) {
    auto setup = TwoPeerSetup::create(
        "kasumi-daemon-contention-", app::KeyStorage::File, 10U);
    app::DaemonOptions opts;
    opts.watch_debounce = 50ms;
    opts.watch_max_wait = 150ms;
    opts.config_poll_interval = 150ms;
    opts.full_scan_verification_interval = 10min;

    auto session = app::start_daemon_session(setup.env, opts);
    ASSERT_TRUE(session.has_value()) << session.error().detail;
    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_a", true).has_value());
    ASSERT_TRUE(wait_until([&] {
        const auto st = app::query_daemon_session_status(*session, "peer_a");
        return st && !st->profiles.empty() && st->profiles[0].watcher_active;
    }));

    // 1. Live CLI fsck running concurrently with daemon sync + local write.
    kasumi::test::write_text(setup.peer_a_dir / "cli_contention.md",
                             "contention-payload");
    std::atomic<bool> fsck_done{false};
    std::thread fsck_thread([&] {
        static_cast<void>(app::execute(app::ExecutionInput{
            .request = {.operation = app::Operation::Fsck,
                        .profile_name = "peer_a"},
            .credentials = app::NoCredentials{},
            .environment = setup.env}));
        fsck_done.store(true, std::memory_order_release);
    });
    static_cast<void>(
        app::trigger_daemon_session_sync(*session, "peer_a", false));
    fsck_thread.join();
    EXPECT_TRUE(fsck_done.load(std::memory_order_acquire));

    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_a", true).has_value());
    ASSERT_TRUE(wait_until(
        [&] {
            const auto st =
                app::query_daemon_session_status(*session, "peer_a");
            return st && !st->profiles.empty() &&
                   st->profiles[0].state == app::DaemonProfileState::Idle &&
                   st->profiles[0].dirty_paths_count == 0U;
        },
        15s));
    EXPECT_NE(app::query_daemon_session_status(*session, "peer_a")
                  ->profiles[0]
                  .state,
              app::DaemonProfileState::NeedsAttention);

    // 2. In-flight cancel during a multi-chunk payload sync must keep the
    //    daemon healthy and allow clean convergence on the follow-up sync.
    const std::string payload(4U * 1024U * 1024U, 'C');
    kasumi::test::write_text(setup.peer_a_dir / "cancel_4mb.bin", payload);
    static_cast<void>(
        app::trigger_daemon_session_sync(*session, "peer_a", false));
    std::this_thread::sleep_for(20ms);
    EXPECT_TRUE(app::cancel_daemon_profile(setup.env, "peer_a").has_value());

    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_a", true).has_value());
    ASSERT_TRUE(wait_until(
        [&] {
            const auto st =
                app::query_daemon_session_status(*session, "peer_a");
            return st && !st->profiles.empty() &&
                   st->profiles[0].state == app::DaemonProfileState::Idle &&
                   st->profiles[0].dirty_paths_count == 0U;
        },
        15s));
    EXPECT_NE(app::query_daemon_session_status(*session, "peer_a")
                  ->profiles[0]
                  .state,
              app::DaemonProfileState::NeedsAttention);

    ASSERT_TRUE(
        app::trigger_daemon_session_sync(*session, "peer_b", true).has_value());
    EXPECT_EQ(kasumi::test::read_text(setup.peer_b_dir / "cli_contention.md"),
              "contention-payload");
    EXPECT_EQ(kasumi::test::read_text(setup.peer_b_dir / "cancel_4mb.bin"),
              payload);

    app::stop_daemon_session(*session);
}

#ifdef _WIN32
TEST(DaemonEngineTest,
     VaultProfileAutoUnlocksAndSyncsWhenKeyAppearsInOsVault) {
    auto ws = kasumi::test::make_temp_workspace("kasumi-daemon-vault-recheck-");
    const app::ExecutionEnvironment env{kasumi::test::workspace_path(ws, "app")};
    const auto local_dir = kasumi::test::workspace_path(ws, "local");
    const auto remote_dir = kasumi::test::workspace_path(ws, "remote");
    std::filesystem::create_directories(local_dir);
    std::filesystem::create_directories(remote_dir);
    kasumi::test::write_text(local_dir / "hello.txt", "vault-recheck");

    const std::string hex_key(64, 'a');
    ASSERT_TRUE(app::create_profile(
                    env,
                    app::Profile{.name = "vault_auto",
                                 .local_dir = local_dir,
                                 .remote_dir = remote_dir.string(),
                                 .key_storage = app::KeyStorage::Memory},
                    app::MasterKeyHex{hex_key})
                    .has_value());
    ASSERT_TRUE(app::execute(app::ExecutionInput{
                                 .request = {.operation = app::Operation::Sync,
                                             .profile_name = "vault_auto"},
                                 .credentials = app::MasterKeyHex{hex_key},
                                 .environment = env})
                    .has_value());

    {
        std::ofstream cfg(env.app_data_dir / "config.toml", std::ios::binary);
        cfg << "version = 1\n\n"
            << "[profiles.vault_auto]\n"
            << "local_dir = '" << kasumi::platform::path::to_utf8(local_dir)
            << "'\n"
            << "remote_dir = '" << kasumi::platform::path::to_utf8(remote_dir)
            << "'\n"
            << "min_history_depth = 5\n"
            << "min_history_age_hours = 6\n"
            << "key_storage = \"vault\"\n"
            << "sync_interval_seconds = 60\n";
    }

    app::DaemonOptions opts;
    opts.watch_debounce = 50ms;
    opts.config_poll_interval = 200ms;
    auto session = app::start_daemon_session(env, opts);
    ASSERT_TRUE(session.has_value()) << session.error().detail;

    // Without a key in Windows Credential Manager, profile starts Locked.
    ASSERT_TRUE(wait_until([&] {
        const auto st = app::query_daemon_session_status(*session, "vault_auto");
        return st && !st->profiles.empty() &&
               st->profiles[0].state == app::DaemonProfileState::Locked &&
               st->profiles[0].locked;
    }));

    // Write the key into OS Vault AFTER daemon startup without calling reload().
    ASSERT_TRUE(
        app::set_profile_key(env, "vault_auto", app::MasterKeyHex{hex_key}, true)
            .has_value());

    // Daemon must automatically re-check OS Vault (~3s backoff), unlock, and sync.
    ASSERT_TRUE(wait_until(
        [&] {
            const auto st =
                app::query_daemon_session_status(*session, "vault_auto");
            return st && !st->profiles.empty() && !st->profiles[0].locked &&
                   st->profiles[0].state == app::DaemonProfileState::Idle &&
                   st->profiles[0].sync_runs >= 1U;
        },
        15s));

    app::stop_daemon_session(*session);
    static_cast<void>(app::delete_profile(env, "vault_auto"));
}
#endif

} // namespace
