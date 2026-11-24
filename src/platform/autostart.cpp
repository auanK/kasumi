#include "platform/autostart.hpp"

#include "platform/path.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cwchar>
#include <expected>
#include <format>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace kasumi::platform {
namespace {

std::optional<std::filesystem::path> hermetic_autostart_dir() {
    auto override_dir = path::environment_value("KASUMI_AUTOSTART_DIR");
    if (!override_dir || override_dir->empty() ||
        !override_dir->is_absolute()) {
        return std::nullopt;
    }
    return *override_dir;
}

std::expected<std::string, std::string>
build_systemd_unit_text(const std::filesystem::path& executable) {
    const auto exe_utf8 = path::to_utf8(executable);
    if (exe_utf8.find('\n') != std::string::npos ||
        exe_utf8.find('\r') != std::string::npos ||
        exe_utf8.find('\0') != std::string::npos) {
        return std::unexpected(
            "executable path contains invalid control characters");
    }
    std::string escaped;
    escaped.reserve(exe_utf8.size() + 8U);
    for (const char ch : exe_utf8) {
        if (ch == '\\' || ch == '"') {
            escaped.push_back('\\');
            escaped.push_back(ch);
        } else if (ch == '%') {
            escaped.append("%%");
        } else if (ch == '$') {
            escaped.append("$$");
        } else {
            escaped.push_back(ch);
        }
    }
    return std::format("[Unit]\n"
                       "Description=Kasumi Background Synchronization Daemon\n"
                       "After=network-online.target\n"
                       "\n"
                       "[Service]\n"
                       "Type=simple\n"
                       "ExecStart=\"{}\" daemon run\n"
                       "Restart=on-failure\n"
                       "RestartSec=5\n"
                       "\n"
                       "[Install]\n"
                       "WantedBy=default.target\n",
                       escaped);
}

#if defined(_WIN32)
std::string build_windows_run_command(const std::filesystem::path& executable) {
    return std::format("\"{}\" daemon run --background",
                       path::to_utf8(executable));
}
#endif

std::expected<AutostartStatus, std::string>
install_hermetic(const std::filesystem::path& dir,
                 const std::filesystem::path& executable) {
    if (auto created = private_storage::ensure_directory(dir); !created) {
        return std::unexpected(created.error());
    }
    const auto file = dir / "kasumi-autostart.conf";
#if defined(_WIN32)
    const auto command = build_windows_run_command(executable);
    const std::string method = "windows-run-key-override";
#else
    const auto command =
        std::format("\"{}\" daemon run", path::to_utf8(executable));
    const std::string method = "systemd-user-override";
#endif
    const auto payload = build_systemd_unit_text(executable);
    if (!payload) {
        return std::unexpected(payload.error());
    }
    if (auto wrote = private_storage::write_atomically(file, *payload);
        !wrote) {
        return std::unexpected(wrote.error());
    }
    return AutostartStatus{
        .supported = true,
        .installed = true,
        .systemd_enabled = false,
        .method = method,
        .location = path::to_utf8(file),
        .command = command,
        .detail = "configured via KASUMI_AUTOSTART_DIR",
    };
}

std::expected<AutostartStatus, std::string>
uninstall_hermetic(const std::filesystem::path& dir) {
    const auto file = dir / "kasumi-autostart.conf";
    std::error_code ec;
    const bool existed = std::filesystem::exists(file, ec);
    if (!ec && existed) {
        std::filesystem::remove(file, ec);
        if (ec) {
            return std::unexpected("failed to remove autostart override: " +
                                   ec.message());
        }
    }
    return AutostartStatus{
        .supported = true,
        .installed = false,
        .systemd_enabled = false,
#if defined(_WIN32)
        .method = "windows-run-key-override",
#else
        .method = "systemd-user-override",
#endif
        .location = path::to_utf8(file),
        .command = {},
        .detail = "removed via KASUMI_AUTOSTART_DIR",
    };
}

std::expected<AutostartStatus, std::string>
query_hermetic(const std::filesystem::path& dir) {
    const auto file = dir / "kasumi-autostart.conf";
    std::error_code ec;
    const bool exists = std::filesystem::is_regular_file(file, ec);
    std::string command;
    if (exists) {
        std::ifstream in(file);
        std::string line;
        while (std::getline(in, line)) {
            constexpr std::string_view prefix = "ExecStart=";
            if (line.starts_with(prefix)) {
                command = line.substr(prefix.size());
                break;
            }
        }
    }
    return AutostartStatus{
        .supported = true,
        .installed = exists,
        .systemd_enabled = false,
#if defined(_WIN32)
        .method = "windows-run-key-override",
#else
        .method = "systemd-user-override",
#endif
        .location = path::to_utf8(file),
        .command = std::move(command),
        .detail =
            exists ? "configured via KASUMI_AUTOSTART_DIR" : "not installed",
    };
}

#if defined(_WIN32)

constexpr wchar_t kRunKeySubpath[] =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kRunValueName[] = L"KasumiDaemon";

std::expected<std::wstring, std::string> to_wide(std::string_view utf8) {
    if (utf8.empty()) {
        return std::wstring{};
    }
    const int needed = MultiByteToWideChar(CP_UTF8,
                                           MB_ERR_INVALID_CHARS,
                                           utf8.data(),
                                           static_cast<int>(utf8.size()),
                                           nullptr,
                                           0);
    if (needed <= 0) {
        return std::unexpected("failed to encode autostart command");
    }
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    if (MultiByteToWideChar(CP_UTF8,
                            MB_ERR_INVALID_CHARS,
                            utf8.data(),
                            static_cast<int>(utf8.size()),
                            out.data(),
                            needed) != needed) {
        return std::unexpected("failed to encode autostart command");
    }
    return out;
}

std::expected<std::string, std::string> from_wide(std::wstring_view wide) {
    if (wide.empty()) {
        return std::string{};
    }
    const int needed = WideCharToMultiByte(CP_UTF8,
                                           WC_ERR_INVALID_CHARS,
                                           wide.data(),
                                           static_cast<int>(wide.size()),
                                           nullptr,
                                           0,
                                           nullptr,
                                           nullptr);
    if (needed <= 0) {
        return std::unexpected("failed to decode autostart command");
    }
    std::string out(static_cast<std::size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8,
                            WC_ERR_INVALID_CHARS,
                            wide.data(),
                            static_cast<int>(wide.size()),
                            out.data(),
                            needed,
                            nullptr,
                            nullptr) != needed) {
        return std::unexpected("failed to decode autostart command");
    }
    return out;
}

#else

std::expected<std::filesystem::path, std::string> systemd_user_unit_path() {
    std::filesystem::path config_root;
    if (const auto xdg = path::environment_value("XDG_CONFIG_HOME");
        xdg && xdg->is_absolute()) {
        config_root = *xdg;
    } else if (const auto home = path::environment_value("HOME");
               home && home->is_absolute()) {
        config_root = *home / ".config";
    } else {
        struct passwd pwd{};
        struct passwd* result = nullptr;
        std::vector<char> buf(16384U);
        if (::getpwuid_r(::geteuid(), &pwd, buf.data(), buf.size(), &result) ==
                0 &&
            result != nullptr && pwd.pw_dir != nullptr) {
            config_root = std::filesystem::path{pwd.pw_dir} / ".config";
        }
    }
    if (config_root.empty()) {
        return std::unexpected("could not determine user config directory");
    }
    return config_root / "systemd" / "user" / "kasumi-daemon.service";
}

bool run_systemctl_user(const std::vector<const char*>& args,
                        std::string* captured_out = nullptr) {
    const auto bin = []() -> const char* {
        if (::access("/usr/bin/systemctl", X_OK) == 0) {
            return "/usr/bin/systemctl";
        }
        if (::access("/bin/systemctl", X_OK) == 0) {
            return "/bin/systemctl";
        }
        if (::access("/run/current-system/sw/bin/systemctl", X_OK) == 0) {
            return "/run/current-system/sw/bin/systemctl";
        }
        return nullptr;
    }();
    if (bin == nullptr) {
        return false;
    }

    int pipe_fd[2]{-1, -1};
    if (captured_out != nullptr && ::pipe(pipe_fd) != 0) {
        return false;
    }
    const pid_t pid = ::fork();
    if (pid < 0) {
        if (pipe_fd[0] >= 0) {
            static_cast<void>(::close(pipe_fd[0]));
            static_cast<void>(::close(pipe_fd[1]));
        }
        return false;
    }
    if (pid == 0) {
        const int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            static_cast<void>(::dup2(devnull, STDIN_FILENO));
            static_cast<void>(::dup2(devnull, STDERR_FILENO));
            if (captured_out == nullptr) {
                static_cast<void>(::dup2(devnull, STDOUT_FILENO));
            }
            static_cast<void>(::close(devnull));
        }
        if (captured_out != nullptr) {
            static_cast<void>(::close(pipe_fd[0]));
            static_cast<void>(::dup2(pipe_fd[1], STDOUT_FILENO));
            static_cast<void>(::close(pipe_fd[1]));
        }
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(bin));
        argv.push_back(const_cast<char*>("--user"));
        for (const char* arg : args) {
            argv.push_back(const_cast<char*>(arg));
        }
        argv.push_back(nullptr);
        ::execv(bin, argv.data());
        ::_exit(127);
    }

    if (pipe_fd[1] >= 0) {
        static_cast<void>(::close(pipe_fd[1]));
    }
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{2};
    if (captured_out != nullptr && pipe_fd[0] >= 0) {
        std::array<char, 256> buf{};
        for (;;) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                break;
            }
            const int remaining_ms = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline -
                                                                      now)
                    .count());
            struct pollfd pfd{.fd = pipe_fd[0], .events = POLLIN, .revents = 0};
            const int prc = ::poll(&pfd, 1, std::max(1, remaining_ms));
            if (prc > 0 && (pfd.revents & (POLLIN | POLLHUP)) != 0) {
                const ssize_t n = ::read(pipe_fd[0], buf.data(), buf.size());
                if (n > 0) {
                    captured_out->append(buf.data(),
                                         static_cast<std::size_t>(n));
                    continue;
                }
                break;
            }
            if (prc == 0 || errno != EINTR) {
                break;
            }
        }
        static_cast<void>(::close(pipe_fd[0]));
    }
    int status = 0;
    for (;;) {
        const pid_t w = ::waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
        if (w < 0 && errno != EINTR) {
            return false;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            static_cast<void>(::kill(pid, SIGKILL));
            while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
            }
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
}

#endif

} // namespace

std::expected<std::filesystem::path, std::string> current_executable_path() {
#if defined(_WIN32)
    std::wstring buf(512U, L'\0');
    for (;;) {
        const DWORD len = GetModuleFileNameW(
            nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (len == 0) {
            return std::unexpected(
                "GetModuleFileNameW failed: " +
                std::to_string(static_cast<unsigned long>(GetLastError())));
        }
        if (len < buf.size()) {
            buf.resize(len);
            return std::filesystem::path{buf};
        }
        if (buf.size() >= 32768U) {
            return std::unexpected("executable path exceeds buffer limit");
        }
        buf.resize(buf.size() * 2U);
    }
#else
    std::vector<char> buf(1024U, '\0');
    for (;;) {
        const ssize_t len =
            ::readlink("/proc/self/exe", buf.data(), buf.size());
        if (len < 0) {
            return std::unexpected("failed to resolve /proc/self/exe: " +
                                   std::to_string(errno));
        }
        if (static_cast<std::size_t>(len) < buf.size()) {
            return std::filesystem::path{
                std::string(buf.data(), static_cast<std::size_t>(len))};
        }
        if (buf.size() >= 32768U) {
            return std::unexpected("executable path exceeds buffer limit");
        }
        buf.resize(buf.size() * 2U);
    }
#endif
}

std::expected<AutostartStatus, std::string>
install_user_autostart(const std::filesystem::path& executable_path) {
    if (executable_path.empty() || !executable_path.is_absolute()) {
        return std::unexpected("autostart executable must be an absolute path");
    }
    if (const auto override_dir = hermetic_autostart_dir()) {
        return install_hermetic(*override_dir, executable_path);
    }

#if defined(_WIN32)
    const auto command = build_windows_run_command(executable_path);
    auto wide_cmd = to_wide(command);
    if (!wide_cmd) {
        return std::unexpected(wide_cmd.error());
    }
    HKEY key = nullptr;
    const LONG open_rc = RegCreateKeyExW(HKEY_CURRENT_USER,
                                         kRunKeySubpath,
                                         0,
                                         nullptr,
                                         REG_OPTION_NON_VOLATILE,
                                         KEY_SET_VALUE | KEY_QUERY_VALUE,
                                         nullptr,
                                         &key,
                                         nullptr);
    if (open_rc != ERROR_SUCCESS) {
        return std::unexpected(
            "failed to open HKCU Run key: " +
            std::error_code{static_cast<int>(open_rc), std::system_category()}
                .message());
    }
    const DWORD byte_count =
        static_cast<DWORD>((wide_cmd->size() + 1U) * sizeof(wchar_t));
    const LONG set_rc =
        RegSetValueExW(key,
                       kRunValueName,
                       0,
                       REG_SZ,
                       reinterpret_cast<const BYTE*>(wide_cmd->c_str()),
                       byte_count);
    RegCloseKey(key);
    if (set_rc != ERROR_SUCCESS) {
        return std::unexpected(
            "failed to write HKCU Run value: " +
            std::error_code{static_cast<int>(set_rc), std::system_category()}
                .message());
    }
    return AutostartStatus{
        .supported = true,
        .installed = true,
        .systemd_enabled = false,
        .method = "windows-run-key",
        .location =
            R"(HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KasumiDaemon)",
        .command = command,
        .detail = "installed in current-user logon registry",
    };
#else
    auto unit = systemd_user_unit_path();
    if (!unit) {
        return std::unexpected(unit.error());
    }
    const auto systemd_dir = unit->parent_path();
    const auto config_dir = systemd_dir.parent_path();
    if (auto ec = private_storage::ensure_directory(config_dir); !ec) {
        return std::unexpected(ec.error());
    }
    if (auto ec = private_storage::ensure_directory(systemd_dir); !ec) {
        return std::unexpected(ec.error());
    }
    const auto unit_text = build_systemd_unit_text(executable_path);
    if (!unit_text) {
        return std::unexpected(unit_text.error());
    }
    if (auto ec = private_storage::write_atomically(*unit, *unit_text); !ec) {
        return std::unexpected(ec.error());
    }
    static_cast<void>(run_systemctl_user({"daemon-reload"}));
    const bool enabled =
        run_systemctl_user({"enable", "kasumi-daemon.service"});
    return AutostartStatus{
        .supported = true,
        .installed = true,
        .systemd_enabled = enabled,
        .method = "systemd-user",
        .location = path::to_utf8(*unit),
        .command =
            std::format("\"{}\" daemon run", path::to_utf8(executable_path)),
        .detail = enabled ? "systemd user unit written and enabled"
                          : "systemd user unit written (enable manually if "
                            "user bus is inactive)",
    };
#endif
}

std::expected<AutostartStatus, std::string> uninstall_user_autostart() {
    if (const auto override_dir = hermetic_autostart_dir()) {
        return uninstall_hermetic(*override_dir);
    }

#if defined(_WIN32)
    HKEY key = nullptr;
    const LONG open_rc = RegOpenKeyExW(HKEY_CURRENT_USER,
                                       kRunKeySubpath,
                                       0,
                                       KEY_SET_VALUE | KEY_QUERY_VALUE,
                                       &key);
    if (open_rc == ERROR_FILE_NOT_FOUND) {
        return AutostartStatus{
            .supported = true,
            .installed = false,
            .systemd_enabled = false,
            .method = "windows-run-key",
            .location =
                R"(HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KasumiDaemon)",
            .detail = "not installed",
        };
    }
    if (open_rc != ERROR_SUCCESS) {
        return std::unexpected(
            "failed to open HKCU Run key: " +
            std::error_code{static_cast<int>(open_rc), std::system_category()}
                .message());
    }
    const LONG del_rc = RegDeleteValueW(key, kRunValueName);
    RegCloseKey(key);
    if (del_rc != ERROR_SUCCESS && del_rc != ERROR_FILE_NOT_FOUND) {
        return std::unexpected(
            "failed to remove HKCU Run value: " +
            std::error_code{static_cast<int>(del_rc), std::system_category()}
                .message());
    }
    return AutostartStatus{
        .supported = true,
        .installed = false,
        .systemd_enabled = false,
        .method = "windows-run-key",
        .location =
            R"(HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KasumiDaemon)",
        .detail = "removed from current-user logon registry",
    };
#else
    auto unit = systemd_user_unit_path();
    if (!unit) {
        return std::unexpected(unit.error());
    }
    static_cast<void>(
        run_systemctl_user({"disable", "--now", "kasumi-daemon.service"}));
    std::error_code ec;
    if (std::filesystem::exists(*unit, ec) && !ec) {
        std::filesystem::remove(*unit, ec);
        if (ec) {
            return std::unexpected("failed to remove systemd unit: " +
                                   ec.message());
        }
    }
    static_cast<void>(run_systemctl_user({"daemon-reload"}));
    return AutostartStatus{
        .supported = true,
        .installed = false,
        .systemd_enabled = false,
        .method = "systemd-user",
        .location = path::to_utf8(*unit),
        .detail = "removed systemd user unit",
    };
#endif
}

std::expected<AutostartStatus, std::string> query_user_autostart() {
    if (const auto override_dir = hermetic_autostart_dir()) {
        return query_hermetic(*override_dir);
    }

#if defined(_WIN32)
    HKEY key = nullptr;
    const LONG open_rc = RegOpenKeyExW(
        HKEY_CURRENT_USER, kRunKeySubpath, 0, KEY_QUERY_VALUE, &key);
    if (open_rc == ERROR_FILE_NOT_FOUND) {
        return AutostartStatus{
            .supported = true,
            .installed = false,
            .systemd_enabled = false,
            .method = "windows-run-key",
            .location =
                R"(HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KasumiDaemon)",
            .detail = "not installed",
        };
    }
    if (open_rc != ERROR_SUCCESS) {
        return std::unexpected(
            "failed to open HKCU Run key: " +
            std::error_code{static_cast<int>(open_rc), std::system_category()}
                .message());
    }
    DWORD type = 0;
    DWORD byte_count = 0;
    const LONG query_rc = RegQueryValueExW(
        key, kRunValueName, nullptr, &type, nullptr, &byte_count);
    if (query_rc == ERROR_FILE_NOT_FOUND ||
        (type != REG_SZ && type != REG_EXPAND_SZ)) {
        RegCloseKey(key);
        return AutostartStatus{
            .supported = true,
            .installed = false,
            .systemd_enabled = false,
            .method = "windows-run-key",
            .location =
                R"(HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KasumiDaemon)",
            .detail = "not installed",
        };
    }
    if (query_rc != ERROR_SUCCESS) {
        RegCloseKey(key);
        return std::unexpected(
            "failed to query HKCU Run value: " +
            std::error_code{static_cast<int>(query_rc), std::system_category()}
                .message());
    }
    std::wstring wide_value;
    LONG read_rc = ERROR_MORE_DATA;
    for (int attempt = 0; attempt < 4 && read_rc == ERROR_MORE_DATA;
         ++attempt) {
        wide_value.assign((byte_count / sizeof(wchar_t)) + 2U, L'\0');
        DWORD buf_bytes =
            static_cast<DWORD>(wide_value.size() * sizeof(wchar_t));
        read_rc = RegQueryValueExW(key,
                                   kRunValueName,
                                   nullptr,
                                   &type,
                                   reinterpret_cast<BYTE*>(wide_value.data()),
                                   &buf_bytes);
        byte_count = buf_bytes;
    }
    RegCloseKey(key);
    if (read_rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        return std::unexpected("failed to read HKCU Run value");
    }
    wide_value.resize(wcsnlen(wide_value.data(), wide_value.size()));
    auto cmd = from_wide(wide_value);
    if (!cmd) {
        return std::unexpected(cmd.error());
    }
    return AutostartStatus{
        .supported = true,
        .installed = true,
        .systemd_enabled = false,
        .method = "windows-run-key",
        .location =
            R"(HKCU\Software\Microsoft\Windows\CurrentVersion\Run\KasumiDaemon)",
        .command = std::move(*cmd),
        .detail = "installed in current-user logon registry",
    };
#else
    auto unit = systemd_user_unit_path();
    if (!unit) {
        return std::unexpected(unit.error());
    }
    std::error_code ec;
    const bool exists = std::filesystem::is_regular_file(*unit, ec);
    std::string command;
    if (exists) {
        std::ifstream in(*unit);
        std::string line;
        while (std::getline(in, line)) {
            constexpr std::string_view prefix = "ExecStart=";
            if (line.starts_with(prefix)) {
                command = line.substr(prefix.size());
                break;
            }
        }
    }
    std::string enabled_out;
    const bool enabled =
        exists &&
        run_systemctl_user({"is-enabled", "kasumi-daemon.service"},
                           &enabled_out) &&
        enabled_out.starts_with("enabled");
    return AutostartStatus{
        .supported = true,
        .installed = exists,
        .systemd_enabled = enabled,
        .method = "systemd-user",
        .location = path::to_utf8(*unit),
        .command = std::move(command),
        .detail = exists ? (enabled ? "systemd user unit installed and enabled"
                                    : "systemd user unit installed")
                         : "not installed",
    };
#endif
}

} // namespace kasumi::platform
