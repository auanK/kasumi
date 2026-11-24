#include "platform/directory_watcher.hpp"

#include "platform/path.hpp"
#include "platform/private_storage.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <exception>
#include <new>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace kasumi::platform {

struct DirectoryWatcherState {
    std::filesystem::path root;
    WatchCallback on_event;
    IgnoreDirectoryFilter skip_dir;
    bool recursive = true;
    std::atomic_bool stop_requested{false};
    std::atomic_bool healthy{true};
    std::thread worker;

#if defined(_WIN32)
    HANDLE dir_handle = INVALID_HANDLE_VALUE;
    HANDLE stop_event = nullptr;
    HANDLE io_event = nullptr;
    HANDLE ready_event = nullptr;
#else
    int inotify_fd = -1;
    int stop_fd = -1;
    // Dense SoA watch-descriptor table indexed linearly & swap-and-popped.
    std::vector<int> watch_descriptors;
    std::vector<std::string> watch_rel_paths;
#endif
};

namespace {

void emit_watch_event(DirectoryWatcherState& state,
                      const WatchEvent& event) noexcept {
    if (event.root_invalidated) {
        state.healthy.store(false, std::memory_order_release);
    }
    if (state.on_event) {
        try {
            state.on_event(event);
        } catch (...) {
        }
    }
}

void close_watcher_handles(DirectoryWatcherState& state) noexcept {
#if defined(_WIN32)
    if (state.dir_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(state.dir_handle);
        state.dir_handle = INVALID_HANDLE_VALUE;
    }
    if (state.io_event != nullptr) {
        CloseHandle(state.io_event);
        state.io_event = nullptr;
    }
    if (state.stop_event != nullptr) {
        CloseHandle(state.stop_event);
        state.stop_event = nullptr;
    }
    if (state.ready_event != nullptr) {
        CloseHandle(state.ready_event);
        state.ready_event = nullptr;
    }
#else
    if (state.inotify_fd >= 0) {
        static_cast<void>(::close(state.inotify_fd));
        state.inotify_fd = -1;
    }
    if (state.stop_fd >= 0) {
        static_cast<void>(::close(state.stop_fd));
        state.stop_fd = -1;
    }
    state.watch_descriptors.clear();
    state.watch_rel_paths.clear();
#endif
}

#if defined(_WIN32)

bool is_plain_directory_path(const std::filesystem::path& path) noexcept {
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES &&
           (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

bool ancestor_dir_skipped(const DirectoryWatcherState& state,
                          std::string_view rel_path) {
    if (!state.recursive && rel_path.find('/') != std::string_view::npos) {
        return true;
    }
    if (!state.skip_dir) {
        return false;
    }
    std::size_t slash = rel_path.find('/');
    while (slash != std::string_view::npos) {
        if (slash > 0 && state.skip_dir(rel_path.substr(0, slash))) {
            return true;
        }
        slash = rel_path.find('/', slash + 1U);
    }
    return false;
}

void run_windows_watch_loop(DirectoryWatcherState& state) noexcept {
    constexpr DWORD kBufferBytes = 64U * 1024U;
    constexpr DWORD kNotifyFilter =
        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
        FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
        FILE_NOTIFY_CHANGE_LAST_WRITE;
    constexpr std::size_t kNotifyHeaderSize =
        offsetof(FILE_NOTIFY_INFORMATION, FileName);
    alignas(DWORD) std::vector<std::uint8_t> buffer(kBufferBytes);
    bool ready_signaled = false;
    const auto signal_ready = [&]() noexcept {
        if (!ready_signaled && state.ready_event != nullptr) {
            SetEvent(state.ready_event);
            ready_signaled = true;
        }
    };

    while (!state.stop_requested.load(std::memory_order_acquire)) {
        ResetEvent(state.io_event);
        OVERLAPPED overlapped{};
        overlapped.hEvent = state.io_event;
        DWORD bytes_returned = 0;

        if (!ReadDirectoryChangesW(state.dir_handle,
                                   buffer.data(),
                                   static_cast<DWORD>(buffer.size()),
                                   state.recursive ? TRUE : FALSE,
                                   kNotifyFilter,
                                   &bytes_returned,
                                   &overlapped,
                                   nullptr)) {
            const DWORD err = GetLastError();
            signal_ready();
            if (err == ERROR_ACCESS_DENIED || err == ERROR_INVALID_HANDLE ||
                err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
                emit_watch_event(state, WatchEvent{.root_invalidated = true});
            } else if (!state.stop_requested.load(std::memory_order_acquire)) {
                emit_watch_event(state, WatchEvent{.overflow = true});
            }
            break;
        }
        signal_ready();

        const std::array<HANDLE, 2> wait_handles{state.stop_event,
                                                 state.io_event};
        const DWORD wait_result =
            WaitForMultipleObjects(2, wait_handles.data(), FALSE, INFINITE);
        if (wait_result == WAIT_OBJECT_0 ||
            state.stop_requested.load(std::memory_order_acquire)) {
            CancelIoEx(state.dir_handle, &overlapped);
            DWORD ignored_bytes = 0;
            static_cast<void>(GetOverlappedResult(
                state.dir_handle, &overlapped, &ignored_bytes, TRUE));
            break;
        }
        if (wait_result != WAIT_OBJECT_0 + 1) {
            emit_watch_event(state, WatchEvent{.root_invalidated = true});
            break;
        }

        if (!GetOverlappedResult(
                state.dir_handle, &overlapped, &bytes_returned, FALSE)) {
            const DWORD err = GetLastError();
            if (err == ERROR_OPERATION_ABORTED ||
                state.stop_requested.load(std::memory_order_acquire)) {
                break;
            }
            if (err == ERROR_NOTIFY_ENUM_DIR) {
                emit_watch_event(state, WatchEvent{.overflow = true});
                continue;
            }
            emit_watch_event(state, WatchEvent{.root_invalidated = true});
            break;
        }

        if (bytes_returned == 0) {
            emit_watch_event(state, WatchEvent{.overflow = true});
            continue;
        }

        std::size_t offset = 0;
        while (offset < bytes_returned) {
            FILE_NOTIFY_INFORMATION info{};
            if (offset + kNotifyHeaderSize > bytes_returned) {
                break;
            }
            std::memcpy(&info, buffer.data() + offset, kNotifyHeaderSize);
            const std::size_t name_bytes = info.FileNameLength;
            const std::size_t name_offset = offset + kNotifyHeaderSize;
            if (name_bytes > 0 && name_offset + name_bytes <= bytes_returned) {
                std::wstring name_wide(name_bytes / sizeof(wchar_t), L'\0');
                std::memcpy(
                    name_wide.data(), buffer.data() + name_offset, name_bytes);
                const auto rel_path = platform::path::to_logical_utf8(
                    std::filesystem::path{name_wide});
                if (!ancestor_dir_skipped(state, rel_path)) {
                    const bool is_dir =
                        info.Action != FILE_ACTION_REMOVED &&
                        info.Action != FILE_ACTION_RENAMED_OLD_NAME &&
                        is_plain_directory_path(
                            state.root / std::filesystem::path{name_wide});
                    if (!(is_dir && state.skip_dir &&
                          state.skip_dir(rel_path))) {
                        emit_watch_event(state,
                                         WatchEvent{
                                             .relative_path = rel_path,
                                             .is_directory = is_dir,
                                         });
                    }
                }
            }
            if (info.NextEntryOffset == 0) {
                break;
            }
            offset += info.NextEntryOffset;
        }
    }
}

#else

constexpr std::uint32_t kInotifyMask =
    IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO |
    IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF | IN_DONT_FOLLOW;

std::string join_rel(std::string_view parent, std::string_view child) {
    if (parent.empty()) {
        return std::string{child};
    }
    if (child.empty()) {
        return std::string{parent};
    }
    std::string out;
    out.reserve(parent.size() + 1U + child.size());
    out.append(parent);
    out.push_back('/');
    out.append(child);
    return out;
}

std::size_t find_watch_slot(const DirectoryWatcherState& state,
                            int wd) noexcept {
    for (std::size_t i = 0; i < state.watch_descriptors.size(); ++i) {
        if (state.watch_descriptors[i] == wd) {
            return i;
        }
    }
    return state.watch_descriptors.size();
}

void upsert_watch_slot(DirectoryWatcherState& state,
                       int wd,
                       std::string_view rel_dir) {
    const std::size_t idx = find_watch_slot(state, wd);
    if (idx < state.watch_descriptors.size()) {
        state.watch_rel_paths[idx] = std::string{rel_dir};
    } else {
        state.watch_descriptors.push_back(wd);
        state.watch_rel_paths.emplace_back(rel_dir);
    }
}

void erase_watch_slot(DirectoryWatcherState& state, std::size_t idx) noexcept {
    const std::size_t last = state.watch_descriptors.size() - 1U;
    if (idx != last) {
        state.watch_descriptors[idx] = state.watch_descriptors[last];
        state.watch_rel_paths[idx] = std::move(state.watch_rel_paths[last]);
    }
    state.watch_descriptors.pop_back();
    state.watch_rel_paths.pop_back();
}

struct PendingWatchDir {
    std::filesystem::path abs_dir;
    std::string rel_dir;
};

void remove_watch_subtree(DirectoryWatcherState& state,
                          std::string_view rel_prefix) noexcept {
    if (rel_prefix.empty()) {
        return;
    }
    for (std::size_t i = state.watch_rel_paths.size(); i > 0; --i) {
        const std::size_t idx = i - 1U;
        const std::string_view p = state.watch_rel_paths[idx];
        const bool is_match =
            p == rel_prefix ||
            (p.size() > rel_prefix.size() && p.starts_with(rel_prefix) &&
             p[rel_prefix.size()] == '/');
        if (is_match) {
            const int wd = state.watch_descriptors[idx];
            if (wd >= 0 && state.inotify_fd >= 0) {
                static_cast<void>(::inotify_rm_watch(state.inotify_fd, wd));
            }
            erase_watch_slot(state, idx);
        }
    }
}

bool add_watch_subtree(DirectoryWatcherState& state,
                       const std::filesystem::path& root_abs,
                       std::string_view root_rel,
                       bool emit_preexisting) {
    std::vector<PendingWatchDir> stack;
    stack.push_back(PendingWatchDir{
        .abs_dir = root_abs,
        .rel_dir = std::string{root_rel},
    });
    bool root_registered = false;

    while (!stack.empty()) {
        PendingWatchDir current = std::move(stack.back());
        stack.pop_back();

        if (!current.rel_dir.empty() && state.skip_dir &&
            state.skip_dir(current.rel_dir)) {
            continue;
        }
        struct stat st{};
        if (::lstat(current.abs_dir.c_str(), &st) != 0 ||
            !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
            if (!root_registered) {
                return false;
            }
            continue;
        }
        const int wd = ::inotify_add_watch(
            state.inotify_fd, current.abs_dir.c_str(), kInotifyMask);
        if (wd < 0) {
            if (errno == ENOSPC || errno == EMFILE) {
                emit_watch_event(state, WatchEvent{.overflow = true});
                return true;
            }
            if (!root_registered) {
                return false;
            }
            continue;
        }
        upsert_watch_slot(state, wd, current.rel_dir);
        root_registered = true;

        if (!state.recursive) {
            break;
        }

        DIR* dir = ::opendir(current.abs_dir.c_str());
        if (dir == nullptr) {
            emit_watch_event(state, WatchEvent{.overflow = true});
            continue;
        }
        struct DirGuard {
            DIR* ptr;
            ~DirGuard() {
                if (ptr != nullptr) {
                    ::closedir(ptr);
                }
            }
        } dir_guard{dir};

        std::vector<PendingWatchDir> subdirs;
        while (const dirent* entry = ::readdir(dir)) {
            const std::string_view name{entry->d_name};
            if (name == "." || name == "..") {
                continue;
            }
            const auto child_abs = current.abs_dir / name;
            struct stat child_st{};
            if (::lstat(child_abs.c_str(), &child_st) != 0 ||
                S_ISLNK(child_st.st_mode)) {
                continue;
            }
            const auto child_rel = join_rel(current.rel_dir, name);
            if (S_ISDIR(child_st.st_mode)) {
                if (state.skip_dir && state.skip_dir(child_rel)) {
                    continue;
                }
                if (emit_preexisting) {
                    emit_watch_event(state,
                                     WatchEvent{
                                         .relative_path = child_rel,
                                         .is_directory = true,
                                     });
                }
                subdirs.push_back(PendingWatchDir{
                    .abs_dir = child_abs,
                    .rel_dir = child_rel,
                });
            } else if (S_ISREG(child_st.st_mode) && emit_preexisting) {
                emit_watch_event(state,
                                 WatchEvent{
                                     .relative_path = child_rel,
                                     .is_directory = false,
                                 });
            }
        }
        for (auto it = subdirs.rbegin(); it != subdirs.rend(); ++it) {
            stack.push_back(std::move(*it));
        }
    }
    return root_registered || !root_rel.empty();
}

void run_linux_watch_loop(DirectoryWatcherState& state) noexcept {
    alignas(struct inotify_event) std::array<std::uint8_t, 64U * 1024U> buf{};
    while (!state.stop_requested.load(std::memory_order_acquire)) {
        std::array<struct pollfd, 2> fds{{
            {.fd = state.stop_fd, .events = POLLIN, .revents = 0},
            {.fd = state.inotify_fd, .events = POLLIN, .revents = 0},
        }};
        const int rc = ::poll(fds.data(), fds.size(), -1);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            emit_watch_event(state, WatchEvent{.root_invalidated = true});
            break;
        }
        if ((fds[0].revents & POLLIN) != 0 ||
            state.stop_requested.load(std::memory_order_acquire)) {
            break;
        }
        if ((fds[1].revents & POLLIN) == 0) {
            continue;
        }

        for (;;) {
            const ssize_t nread =
                ::read(state.inotify_fd, buf.data(), buf.size());
            if (nread < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                if (errno == EINTR) {
                    continue;
                }
                emit_watch_event(state, WatchEvent{.root_invalidated = true});
                return;
            }
            if (nread == 0) {
                break;
            }

            ssize_t offset = 0;
            while (offset < nread) {
                if (offset +
                        static_cast<ssize_t>(sizeof(struct inotify_event)) >
                    nread) {
                    break;
                }
                struct inotify_event ev{};
                std::memcpy(&ev, buf.data() + offset, sizeof(ev));
                const ssize_t name_offset =
                    offset + static_cast<ssize_t>(sizeof(struct inotify_event));
                const ssize_t total_size =
                    name_offset + static_cast<ssize_t>(ev.len);
                if (total_size > nread) {
                    break;
                }

                if ((ev.mask & IN_Q_OVERFLOW) != 0) {
                    emit_watch_event(state, WatchEvent{.overflow = true});
                    offset = total_size;
                    continue;
                }

                const std::size_t slot = find_watch_slot(state, ev.wd);
                if (slot >= state.watch_descriptors.size()) {
                    offset = total_size;
                    continue;
                }
                const std::string base_rel = state.watch_rel_paths[slot];

                if (base_rel.empty() &&
                    (ev.mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT)) !=
                        0) {
                    emit_watch_event(state,
                                     WatchEvent{.root_invalidated = true});
                    return;
                }
                if ((ev.mask & IN_IGNORED) != 0) {
                    erase_watch_slot(state, slot);
                    offset = total_size;
                    continue;
                }

                std::string child_name;
                if (ev.len > 0) {
                    const char* raw_name =
                        reinterpret_cast<const char*>(buf.data() + name_offset);
                    const std::size_t max_len = ev.len;
                    const std::size_t actual_len = ::strnlen(raw_name, max_len);
                    child_name.assign(raw_name, actual_len);
                }
                const std::string rel = join_rel(base_rel, child_name);
                const bool is_dir = (ev.mask & IN_ISDIR) != 0;
                if (!rel.empty()) {
                    const bool skipped_dir =
                        is_dir && state.skip_dir && state.skip_dir(rel);
                    if (is_dir &&
                        ((ev.mask & (IN_MOVED_FROM | IN_DELETE)) != 0 ||
                         skipped_dir)) {
                        remove_watch_subtree(state, rel);
                    }
                    if (!skipped_dir) {
                        emit_watch_event(state,
                                         WatchEvent{
                                             .relative_path = rel,
                                             .is_directory = is_dir,
                                         });
                        if (is_dir && state.recursive &&
                            (ev.mask & (IN_CREATE | IN_MOVED_TO)) != 0) {
                            static_cast<void>(add_watch_subtree(
                                state,
                                state.root / platform::path::from_utf8(rel),
                                rel,
                                true));
                        }
                    }
                }
                offset = total_size;
            }
        }
    }
}

#endif

void stop_watcher_state(DirectoryWatcherState& state) noexcept {
    state.stop_requested.store(true, std::memory_order_release);
#if defined(_WIN32)
    if (state.stop_event != nullptr) {
        SetEvent(state.stop_event);
    }
#else
    if (state.stop_fd >= 0) {
        const std::uint64_t one = 1;
        if (::write(state.stop_fd, &one, sizeof(one)) < 0) {
        }
    }
#endif
    if (state.worker.joinable()) {
        state.worker.join();
    }
    close_watcher_handles(state);
}

} // namespace

void destroy_directory_watcher(DirectoryWatcherState* state) noexcept {
    if (state == nullptr) {
        return;
    }
    stop_watcher_state(*state);
    delete state;
}

std::expected<DirectoryWatcher, std::string>
start_directory_watcher(const std::filesystem::path& root,
                        WatchCallback on_event,
                        IgnoreDirectoryFilter skip_dir,
                        bool recursive) {
    if (root.empty() || !root.is_absolute()) {
        return std::unexpected("watch root must be an absolute path");
    }
    std::unique_ptr<DirectoryWatcherState,
                    void (*)(DirectoryWatcherState*) noexcept>
        state_holder{new (std::nothrow) DirectoryWatcherState{},
                     &destroy_directory_watcher};
    if (!state_holder) {
        return std::unexpected(
            "out of memory allocating DirectoryWatcherState");
    }
    auto& state = *state_holder;
    state.root = root;
    state.on_event = std::move(on_event);
    state.skip_dir = std::move(skip_dir);
    state.recursive = recursive;

#if defined(_WIN32)
    if (!private_storage::query_directory_identity(root).valid) {
        return std::unexpected(
            "watch root is not an accessible plain directory");
    }
    state.dir_handle =
        CreateFileW(root.c_str(),
                    FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED |
                        FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr);
    if (state.dir_handle == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        close_watcher_handles(state);
        return std::unexpected(
            "failed to open watch directory: " +
            std::error_code{static_cast<int>(err), std::system_category()}
                .message());
    }
    state.stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    state.io_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    state.ready_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (state.stop_event == nullptr || state.io_event == nullptr ||
        state.ready_event == nullptr) {
        close_watcher_handles(state);
        return std::unexpected("failed to create watch synchronization events");
    }
    auto* raw_state = &state;
    try {
        state.worker = std::thread([raw_state] {
            run_windows_watch_loop(*raw_state);
        });
    } catch (const std::exception& exc) {
        close_watcher_handles(state);
        return std::unexpected(
            std::string{"failed to start directory watcher thread: "} +
            exc.what());
    }
    WaitForSingleObject(raw_state->ready_event, 2000);
#else
    struct stat st{};
    if (::lstat(root.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) ||
        S_ISLNK(st.st_mode)) {
        return std::unexpected(
            "watch root is not an accessible plain directory");
    }
    state.inotify_fd = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    state.stop_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (state.inotify_fd < 0 || state.stop_fd < 0) {
        const int err = errno;
        close_watcher_handles(state);
        return std::unexpected(
            "failed to initialize inotify watcher: " +
            std::error_code{err, std::system_category()}.message());
    }
    if (!add_watch_subtree(state, root, "", false)) {
        close_watcher_handles(state);
        return std::unexpected("failed to register root watch descriptor");
    }
    auto* raw_state = &state;
    try {
        state.worker = std::thread([raw_state] {
            run_linux_watch_loop(*raw_state);
        });
    } catch (const std::exception& exc) {
        close_watcher_handles(state);
        return std::unexpected(
            std::string{"failed to start directory watcher thread: "} +
            exc.what());
    }
#endif

    return DirectoryWatcher{.state = std::move(state_holder)};
}

void stop_directory_watcher(DirectoryWatcher& watcher) noexcept {
    watcher.state.reset();
}

bool directory_watcher_valid(const DirectoryWatcher& watcher) noexcept {
    return watcher.state != nullptr;
}

bool directory_watcher_healthy(const DirectoryWatcher& watcher) noexcept {
    return watcher.state != nullptr &&
           watcher.state->healthy.load(std::memory_order_acquire);
}

} // namespace kasumi::platform
