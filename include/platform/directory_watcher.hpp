#ifndef KASUMI_PLATFORM_DIRECTORY_WATCHER_HPP
#define KASUMI_PLATFORM_DIRECTORY_WATCHER_HPP

#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace kasumi::platform {

struct WatchEvent {
    std::string relative_path;
    bool is_directory = false;
    bool overflow = false;
    bool root_invalidated = false;
};

using WatchCallback = std::function<void(const WatchEvent&)>;
using IgnoreDirectoryFilter =
    std::function<bool(std::string_view relative_dir)>;

struct DirectoryWatcherState;
void destroy_directory_watcher(DirectoryWatcherState* state) noexcept;

// Native recursive directory watcher backed by ReadDirectoryChangesW (Windows)
// and inotify + eventfd (Linux). Ignores symlinks and reparse points.
struct DirectoryWatcher {
    std::unique_ptr<DirectoryWatcherState,
                    void (*)(DirectoryWatcherState*) noexcept>
        state{nullptr, &destroy_directory_watcher};
};

std::expected<DirectoryWatcher, std::string>
start_directory_watcher(const std::filesystem::path& root,
                        WatchCallback on_event,
                        IgnoreDirectoryFilter skip_dir = {},
                        bool recursive = true);
void stop_directory_watcher(DirectoryWatcher& watcher) noexcept;
[[nodiscard]] bool
directory_watcher_valid(const DirectoryWatcher& watcher) noexcept;
[[nodiscard]] bool
directory_watcher_healthy(const DirectoryWatcher& watcher) noexcept;

} // namespace kasumi::platform

#endif
