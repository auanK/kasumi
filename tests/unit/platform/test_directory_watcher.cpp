#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/directory_watcher.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

struct RecordedWatchEvents {
    std::mutex mutex;
    std::condition_variable cv;
    std::vector<kasumi::platform::WatchEvent> events;
};

void record_watch_event(RecordedWatchEvents& recorded,
                        const kasumi::platform::WatchEvent& event) {
    std::lock_guard lock(recorded.mutex);
    recorded.events.push_back(event);
    recorded.cv.notify_all();
}

template <typename Pred>
bool wait_until_watch_events(RecordedWatchEvents& recorded,
                             Pred pred,
                             std::chrono::milliseconds timeout) {
    std::unique_lock lock(recorded.mutex);
    return recorded.cv.wait_for(lock, timeout, [&] {
        return pred(recorded.events);
    });
}

TEST(DirectoryWatcherTest, DetectsFileCreateModifyRenameDeleteAndSubdirs) {
    auto workspace = kasumi::test::make_temp_workspace("kasumi-watch-");
    const auto root = kasumi::test::workspace_path(workspace, "watched");
    std::filesystem::create_directories(root);

    RecordedWatchEvents recorded;
    auto watcher = kasumi::platform::start_directory_watcher(
        root,
        [&](const kasumi::platform::WatchEvent& event) {
            record_watch_event(recorded, event);
        },
        [](std::string_view rel_dir) {
            return rel_dir == "ignored_dir";
        });
    ASSERT_TRUE(watcher.has_value()) << watcher.error();
    EXPECT_TRUE(kasumi::platform::directory_watcher_healthy(*watcher));

    {
        std::ofstream out(root / "alpha.txt", std::ios::binary);
        out << "hello";
    }
    EXPECT_TRUE(wait_until_watch_events(
        recorded,
        [](const auto& events) {
            return std::ranges::any_of(events, [](const auto& ev) {
                return ev.relative_path == "alpha.txt" || ev.overflow;
            });
        },
        std::chrono::seconds(5)));

    std::filesystem::create_directories(root / "sub");
    {
        std::ofstream out(root / "sub" / "beta.txt", std::ios::binary);
        out << "world";
    }
    EXPECT_TRUE(wait_until_watch_events(
        recorded,
        [](const auto& events) {
            return std::ranges::any_of(events, [](const auto& ev) {
                return ev.relative_path == "sub/beta.txt" || ev.overflow;
            });
        },
        std::chrono::seconds(5)));

    std::filesystem::remove(root / "alpha.txt");

    const auto stop_start = std::chrono::steady_clock::now();
    kasumi::platform::stop_directory_watcher(*watcher);
    const auto stop_elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - stop_start);
    EXPECT_LT(stop_elapsed.count(), 1500);
}

TEST(DirectoryWatcherTest, RejectsMissingOrSymlinkRoot) {
    auto workspace = kasumi::test::make_temp_workspace("kasumi-watch-err-");
    const auto missing = kasumi::test::workspace_path(workspace, "missing");
    auto watcher = kasumi::platform::start_directory_watcher(
        missing, [](const kasumi::platform::WatchEvent&) {
        });
    EXPECT_FALSE(watcher.has_value());
}

TEST(DirectoryWatcherTest,
     NonRecursiveWatchReportsTopLevelWithoutSubtreeFiles) {
    auto workspace = kasumi::test::make_temp_workspace("kasumi-watch-flat-");
    const auto root = kasumi::test::workspace_path(workspace, "watched");
    const auto nested = root / "nested";
    std::filesystem::create_directories(nested);

    RecordedWatchEvents recorded;
    auto watcher = kasumi::platform::start_directory_watcher(
        root,
        [&](const kasumi::platform::WatchEvent& event) {
            record_watch_event(recorded, event);
        },
        {},
        false);
    ASSERT_TRUE(watcher.has_value()) << watcher.error();

    {
        std::ofstream out(nested / "inside.txt", std::ios::binary);
        out << "nested";
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    {
        std::ofstream out(root / "top.txt", std::ios::binary);
        out << "top";
    }
    EXPECT_TRUE(wait_until_watch_events(
        recorded,
        [](const auto& events) {
            return std::ranges::any_of(events, [](const auto& ev) {
                return ev.relative_path == "top.txt";
            });
        },
        std::chrono::seconds(5)));
    {
        std::lock_guard lock(recorded.mutex);
        for (const auto& ev : recorded.events) {
            EXPECT_EQ(ev.relative_path.find("nested/inside.txt"),
                      std::string::npos);
        }
    }
    kasumi::platform::stop_directory_watcher(*watcher);
}

} // namespace
