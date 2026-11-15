#include "cli/update.hpp"

#include "cli/i18n.hpp"
#include "cli/presenter.hpp"
#include "crypto/physical_hash.hpp"
#include "platform/cancellation.hpp"
#include "platform/durability.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"
#include "platform/workspace.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>
#include <print>
#include <reproc++/run.hpp>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <aclapi.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <windows.h>
#include <winhttp.h>
#include <winver.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace kasumi::cli::update {
namespace {

using Json = nlohmann::json;
constexpr std::string_view GITHUB_REPOSITORY = "auanK/kasumi";
constexpr std::size_t API_RESPONSE_LIMIT = 8U * 1024U * 1024U;
constexpr std::size_t PACKAGE_LIMIT = 128U * 1024U * 1024U;
constexpr std::size_t EXECUTABLE_LIMIT = 96U * 1024U * 1024U;
constexpr std::size_t PACKAGE_DOCUMENT_LIMIT = 2U * 1024U * 1024U;
constexpr std::size_t PROCESS_OUTPUT_LIMIT = 64U * 1024U;

#if defined(__linux__)
constexpr std::array<std::string_view, 7> LINUX_SYSTEM_TOOLS{
    "curl", "tar", "dpkg-query", "rpm", "pacman", "apk", "pkexec"};
constexpr std::array<std::string_view, 1> LINUX_ELEVATION_TOOLS{"sudo"};
constexpr std::array<std::string_view, 6> LINUX_TOOL_DIRECTORIES{
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin"};

bool trusted_root_stat(const struct stat& status, bool directory) {
    return status.st_uid == 0 && (status.st_mode & 0022) == 0 &&
           (directory ? S_ISDIR(status.st_mode) : S_ISREG(status.st_mode));
}

std::expected<void, std::string>
validate_root_path(const std::filesystem::path& path,
                   bool final_directory,
                   bool allow_root_symlinks) {
    if (!path.is_absolute() || path.lexically_normal() != path) {
        return std::unexpected(
            "system tool path is not an absolute normalized path");
    }
    struct stat status{};
    if (::lstat("/", &status) != 0 || !trusted_root_stat(status, true)) {
        return std::unexpected("root directory is not root-controlled");
    }
    auto current = std::filesystem::path{"/"};
    const auto components = path.relative_path();
    for (auto iterator = components.begin(); iterator != components.end();
         ++iterator) {
        if (*iterator == "." || *iterator == ".." || iterator->empty()) {
            return std::unexpected(
                "system tool path contains an unsafe component");
        }
        current /= *iterator;
        if (::lstat(current.c_str(), &status) != 0) {
            return std::unexpected(
                "system tool path cannot be inspected safely");
        }
        if (allow_root_symlinks && S_ISLNK(status.st_mode)) {
            if (status.st_uid != 0) {
                return std::unexpected(
                    "system tool path contains a non-root symlink");
            }
            continue;
        }
        const bool is_dir =
            std::next(iterator) != components.end() || final_directory;
        if (!trusted_root_stat(status, is_dir)) {
            return std::unexpected(
                "system tool path contains an untrusted or writable entry");
        }
    }
    return {};
}

bool trusted_canonical_path(const std::filesystem::path& path,
                            bool final_directory) {
    return validate_root_path(path, final_directory, false).has_value();
}

bool trusted_system_directory(const std::filesystem::path& path,
                              std::filesystem::path* canonical = nullptr) {
    std::error_code error;
    struct stat status{};
    if (!path.is_absolute() || path.lexically_normal() != path ||
        ::lstat(path.c_str(), &status) != 0 || status.st_uid != 0 ||
        (!S_ISDIR(status.st_mode) && !S_ISLNK(status.st_mode)) ||
        (S_ISDIR(status.st_mode) && (status.st_mode & 0022) != 0)) {
        return false;
    }
    const auto resolved = std::filesystem::canonical(path, error);
    if (error || !trusted_canonical_path(resolved, true)) {
        return false;
    }
    if (canonical != nullptr) {
        *canonical = resolved;
    }
    return true;
}

std::vector<std::filesystem::path> linux_tool_directories() {
    std::vector<std::filesystem::path> directories;
    for (const auto directory : LINUX_TOOL_DIRECTORIES) {
        std::filesystem::path resolved;
        if (!trusted_system_directory(platform::path::from_utf8(directory),
                                      &resolved) ||
            std::ranges::find(directories, resolved) != directories.end()) {
            continue;
        }
        directories.push_back(std::move(resolved));
    }
    return directories;
}

std::string linux_trusted_path_value() {
    std::string result;
    for (const auto& directory : linux_tool_directories()) {
        if (!result.empty()) {
            result.push_back(':');
        }
        result += platform::path::to_utf8(directory);
    }
    return result;
}

bool safe_environment_value(const char* value, std::size_t limit) {
    return value != nullptr && std::char_traits<char>::length(value) <= limit &&
           std::string_view{value}.find_first_of("\r\n") ==
               std::string_view::npos;
}

using LinuxEnvironment = std::vector<std::pair<std::string, std::string>>;

void append_safe_env(LinuxEnvironment& environment,
                     std::initializer_list<const char*> names) {
    for (const auto* name : names) {
        if (const char* value = std::getenv(name);
            safe_environment_value(value, 4096)) {
            environment.emplace_back(name, value);
        }
    }
}

LinuxEnvironment linux_base_environment(bool include_proxy = false,
                                        bool allow_when_root = false) {
    LinuxEnvironment environment{
        {"PATH", linux_trusted_path_value()}, {"LANG", "C"}, {"LC_ALL", "C"}};
    if (include_proxy && (allow_when_root || ::geteuid() != 0)) {
        append_safe_env(environment,
                        {"http_proxy",
                         "https_proxy",
                         "HTTP_PROXY",
                         "HTTPS_PROXY",
                         "all_proxy",
                         "ALL_PROXY",
                         "no_proxy",
                         "NO_PROXY"});
    }
    return environment;
}

LinuxEnvironment linux_pkexec_environment() {
    auto environment = linux_base_environment();
    append_safe_env(environment,
                    {"DISPLAY",
                     "WAYLAND_DISPLAY",
                     "XAUTHORITY",
                     "DBUS_SESSION_BUS_ADDRESS",
                     "XDG_RUNTIME_DIR"});
    if (const char* term = std::getenv("TERM");
        safe_environment_value(term, 64) &&
        std::ranges::all_of(std::string_view{term},
                            [](unsigned char character) {
                                return (character >= 'a' && character <= 'z') ||
                                       (character >= 'A' && character <= 'Z') ||
                                       (character >= '0' && character <= '9') ||
                                       character == '_' || character == '-' ||
                                       character == '.' || character == '+';
                            })) {
        environment.emplace_back("TERM", term);
    }
    return environment;
}
#endif

bool ascii_alphanumeric(char character) noexcept {
    return (character >= 'a' && character <= 'z') ||
           (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9');
}

bool valid_identifier(std::string_view value, bool allow_leading_zero) {
    if (value.empty()) {
        return false;
    }
    const bool numeric = std::ranges::all_of(value, [](char character) {
        return character >= '0' && character <= '9';
    });
    if (!allow_leading_zero && numeric && value.size() > 1 &&
        value.front() == '0') {
        return false;
    }
    return std::ranges::all_of(value, [](char character) {
        return ascii_alphanumeric(character) || character == '-';
    });
}

std::vector<std::string_view> split(std::string_view value, char separator) {
    std::vector<std::string_view> result;
    std::size_t begin = 0;
    while (begin <= value.size()) {
        const auto end = value.find(separator, begin);
        if (end == std::string_view::npos) {
            result.push_back(value.substr(begin));
            break;
        }
        result.push_back(value.substr(begin, end - begin));
        begin = end + 1;
    }
    return result;
}

bool is_numeric_identifier(std::string_view value) noexcept {
    return !value.empty() && std::ranges::all_of(value, [](char character) {
        return character >= '0' && character <= '9';
    });
}

std::strong_ordering compare_identifier(std::string_view left,
                                        std::string_view right) noexcept {
    const bool left_numeric = is_numeric_identifier(left);
    const bool right_numeric = is_numeric_identifier(right);
    if (left_numeric != right_numeric) {
        return left_numeric ? std::strong_ordering::less
                            : std::strong_ordering::greater;
    }
    if (left_numeric) {
        if (left.size() != right.size()) {
            return left.size() < right.size() ? std::strong_ordering::less
                                              : std::strong_ordering::greater;
        }
    }
    if (left < right) {
        return std::strong_ordering::less;
    }
    if (left > right) {
        return std::strong_ordering::greater;
    }
    return std::strong_ordering::equal;
}

std::string lower_ascii(std::string_view value) {
    std::string result{value};
    std::ranges::transform(result, result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

bool is_hex_string(std::string_view value) noexcept {
    return std::ranges::all_of(value, [](char character) {
        return (character >= '0' && character <= '9') ||
               (character >= 'a' && character <= 'f') ||
               (character >= 'A' && character <= 'F');
    });
}

bool valid_sha256(std::string_view value) noexcept {
    return value.size() == 64 && is_hex_string(value);
}

struct ProcessResult {
    int exit_code = -1;
    std::string output;
    std::string error_output;
};

struct CappedSink {
    std::string value;
    std::size_t limit = 0;

    std::error_code
    operator()(reproc::stream, const std::uint8_t* bytes, std::size_t size) {
        if (size > limit - std::min(limit, value.size())) {
            return std::make_error_code(std::errc::file_too_large);
        }
        value.append(reinterpret_cast<const char*>(bytes), size);
        return {};
    }
};

reproc::stop_actions default_process_stop_actions() {
    return reproc::stop_actions{
        {reproc::stop::wait, reproc::milliseconds{300000}},
        {reproc::stop::terminate, reproc::milliseconds{1000}},
        {reproc::stop::kill, reproc::milliseconds{1000}},
    };
}

#if defined(__linux__)
void apply_linux_process_environment(reproc::options& options,
                                     LinuxEnvironment& environment) {
    options.env.behavior = reproc::env::empty;
    options.env.extra = environment;
    options.working_directory = "/";
}
#endif

std::expected<ProcessResult, std::string>
run_capture(const std::vector<std::string>& arguments,
            std::size_t output_limit = PROCESS_OUTPUT_LIMIT,
            std::size_t error_limit = 8192,
            bool inherit_in_out = false
#if defined(__linux__)
            ,
            const LinuxEnvironment* custom_environment = nullptr
#endif
) {
    if (arguments.empty()) {
        return std::unexpected("process command is empty");
    }
    auto child_arguments = arguments;
    reproc::options options;
    options.redirect.in.type =
        inherit_in_out ? reproc::redirect::parent : reproc::redirect::default_;
    options.redirect.out.type =
        inherit_in_out ? reproc::redirect::parent : reproc::redirect::pipe;
    options.redirect.err.type = reproc::redirect::pipe;
    options.stop = default_process_stop_actions();
#if defined(__linux__)
    const auto tool = resolve_linux_system_tool(arguments.front());
    if (!tool) {
        return std::unexpected(tool.error());
    }
    child_arguments.front() = platform::path::to_utf8(*tool);
    auto environment =
        custom_environment != nullptr
            ? *custom_environment
            : linux_base_environment(arguments.front() == "curl");
    apply_linux_process_environment(options, environment);
#endif
    CappedSink output{.limit = output_limit};
    CappedSink error_output{.limit = error_limit};
    const auto [exit_code, error] =
        inherit_in_out ? reproc::run(reproc::arguments{child_arguments},
                                     options,
                                     reproc::sink::null,
                                     error_output)
                       : reproc::run(reproc::arguments{child_arguments},
                                     options,
                                     output,
                                     error_output);
    if (error) {
        return std::unexpected("process failed: " + error.message());
    }
    return ProcessResult{.exit_code = exit_code,
                         .output = std::move(output.value),
                         .error_output = std::move(error_output.value)};
}

#if defined(__linux__)
std::expected<void, std::string>
run_inherited(const std::vector<std::string>& arguments) {
    if (arguments.empty()) {
        return std::unexpected("elevated installer command is empty");
    }
    auto child_arguments = arguments;
    reproc::options options;
#if defined(__linux__)
    const auto tool = resolve_linux_system_tool("sudo");
    if (!tool) {
        return std::unexpected(tool.error());
    }
    child_arguments.front() = platform::path::to_utf8(*tool);
    auto environment = linux_base_environment();
    if (const char* term = std::getenv("TERM");
        safe_environment_value(term, 64)) {
        environment.emplace_back("TERM", term);
    }
    apply_linux_process_environment(options, environment);
#endif
    const auto [exit_code, error] =
        reproc::run(reproc::arguments{child_arguments}, options);
    if (error) {
        return std::unexpected("could not start elevated installer: " +
                               error.message());
    }
    if (exit_code != 0) {
        return std::unexpected("elevated installer exited with code " +
                               std::to_string(exit_code));
    }
    return {};
}
#endif

std::expected<std::string, std::string>
read_limited_file(const std::filesystem::path& path, std::size_t limit) {
    std::string result;
    std::array<std::uint8_t, 65536> scratch{};
    bool oversized = false;
    const auto streamed = platform::private_storage::stream_regular_file(
        path, scratch, [&](std::span<const std::uint8_t> chunk) {
            if (chunk.size() > limit - std::min(limit, result.size())) {
                oversized = true;
                return false;
            }
            result.append(reinterpret_cast<const char*>(chunk.data()),
                          chunk.size());
            return true;
        });
    if (oversized) {
        return std::unexpected("download exceeds the permitted size");
    }
    if (!streamed) {
        return std::unexpected("download could not be read: " +
                               streamed.error().detail);
    }
    return result;
}

struct UrlParts {
    std::string host;
};

std::optional<UrlParts> parse_https_url(std::string_view url) {
    constexpr std::string_view prefix = "https://";
    if (!url.starts_with(prefix) ||
        url.find_first_of("\r\n\t ") != std::string_view::npos) {
        return std::nullopt;
    }
    const auto authority_begin = prefix.size();
    auto authority_end = url.find_first_of("/?#", authority_begin);
    if (authority_end == std::string_view::npos) {
        authority_end = url.size();
    }
    const auto authority =
        url.substr(authority_begin, authority_end - authority_begin);
    if (authority.empty() || authority.find('@') != std::string_view::npos ||
        authority.find(':') != std::string_view::npos) {
        return std::nullopt;
    }
    const auto host = lower_ascii(authority);
    if (host.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789.-") !=
        std::string::npos) {
        return std::nullopt;
    }
    return UrlParts{.host = host};
}

bool allowed_download_host(std::string_view host) {
    return host == "github.com" || host == "api.github.com" ||
           host == "release-assets.githubusercontent.com" ||
           host == "objects.githubusercontent.com";
}

bool allowed_api_host(std::string_view host) {
    return host == "api.github.com";
}

template <typename StepFn>
auto https_with_redirects(std::string url, bool api_request, StepFn&& step)
    -> decltype(step(url,
                     std::declval<std::string&>(),
                     std::declval<bool&>())) {
    for (int redirect = 0; redirect <= 5; ++redirect) {
        const auto parts = parse_https_url(url);
        if (!parts || !(api_request ? allowed_api_host(parts->host)
                                    : allowed_download_host(parts->host))) {
            return std::unexpected(
                "download URL is outside the GitHub allowlist");
        }
        std::string next_url;
        bool is_redirect = false;
        auto result = step(url, next_url, is_redirect);
        if (!result || !is_redirect) {
            return result;
        }
        const auto next = parse_https_url(next_url);
        if (api_request || !next || !allowed_download_host(next->host) ||
            redirect == 5) {
            return std::unexpected("GitHub redirect was rejected");
        }
        url = std::move(next_url);
    }
    return std::unexpected("too many GitHub redirects");
}

#if !defined(_WIN32)
std::vector<std::string> base_curl_args(std::string executable,
                                        std::size_t maximum_bytes,
                                        int max_time_seconds) {
    return {std::move(executable),
            "--disable",
            "--silent",
            "--show-error",
            "--globoff",
            "--proto",
            "=https",
            "--connect-timeout",
            "15",
            "--max-time",
            std::to_string(max_time_seconds),
            "--max-filesize",
            std::to_string(maximum_bytes)};
}

struct CurlWriteOut {
    int status{0};
    std::string redirect_url;
    std::string body;
};

std::expected<CurlWriteOut, std::string>
parse_curl_write_out(std::string_view output, bool has_body_prefix) {
    const auto second_sep = output.rfind('\n');
    const auto first_sep =
        second_sep == std::string_view::npos || second_sep == 0
            ? std::string_view::npos
            : output.rfind('\n', second_sep - 1);
    const auto code_begin =
        has_body_prefix
            ? (first_sep == std::string_view::npos ? std::string_view::npos
                                                   : first_sep + 1)
            : 0;
    if (second_sep == std::string_view::npos ||
        code_begin == std::string_view::npos) {
        return std::unexpected("could not read HTTP response status");
    }
    int status = 0;
    const auto code_view = output.substr(code_begin, second_sep - code_begin);
    const auto [end, parse_err] = std::from_chars(
        code_view.data(), code_view.data() + code_view.size(), status);
    if (parse_err != std::errc{} ||
        end != code_view.data() + code_view.size()) {
        return std::unexpected("could not read HTTP response status");
    }
    return CurlWriteOut{
        .status = status,
        .redirect_url = std::string{output.substr(second_sep + 1)},
        .body = has_body_prefix ? std::string{output.substr(0, first_sep)}
                                : std::string{}};
}
#endif

#if defined(_WIN32)

struct ScopedWindowsHandle {
    HANDLE value = nullptr;
    ScopedWindowsHandle() = default;
    explicit ScopedWindowsHandle(HANDLE handle) noexcept : value(handle) {
    }
    ScopedWindowsHandle(const ScopedWindowsHandle&) = delete;
    ScopedWindowsHandle& operator=(const ScopedWindowsHandle&) = delete;
    ~ScopedWindowsHandle() {
        if (value != nullptr && value != INVALID_HANDLE_VALUE) {
            CloseHandle(value);
        }
    }
    explicit operator bool() const noexcept {
        return value != nullptr && value != INVALID_HANDLE_VALUE;
    }
};

struct LocalFreeDeleter {
    void operator()(void* ptr) const noexcept {
        if (ptr != nullptr) {
            LocalFree(ptr);
        }
    }
};

using LocalSecurityDescriptor = std::unique_ptr<void, LocalFreeDeleter>;

bool windows_has_attribute_flags(const std::filesystem::path& path,
                                 DWORD flags,
                                 DWORD forbidden_attributes,
                                 FILE_ID_INFO* out_id = nullptr) {
    const ScopedWindowsHandle handle{
        CreateFileW(path.c_str(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | flags,
                    nullptr)};
    if (!handle) {
        return false;
    }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (GetFileInformationByHandleEx(handle.value,
                                     FileAttributeTagInfo,
                                     &attributes,
                                     sizeof(attributes)) == 0 ||
        (attributes.FileAttributes & forbidden_attributes) != 0) {
        return false;
    }
    return out_id == nullptr ||
           GetFileInformationByHandleEx(
               handle.value, FileIdInfo, out_id, sizeof(*out_id)) != 0;
}

std::string bytes_to_hex(std::span<const std::uint8_t> bytes) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        result.push_back(hex[byte >> 4U]);
        result.push_back(hex[byte & 0x0fU]);
    }
    return result;
}

struct InternetHandle {
    HINTERNET value = nullptr;
    ~InternetHandle() {
        if (value != nullptr) {
            WinHttpCloseHandle(value);
        }
    }
};

std::optional<std::wstring> widen_ascii(std::string_view value) {
    if (value.size() > static_cast<std::size_t>(INT_MAX)) {
        return std::nullopt;
    }
    const int count = MultiByteToWideChar(CP_UTF8,
                                          MB_ERR_INVALID_CHARS,
                                          value.data(),
                                          static_cast<int>(value.size()),
                                          nullptr,
                                          0);
    if (count <= 0) {
        return std::nullopt;
    }
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    if (MultiByteToWideChar(CP_UTF8,
                            MB_ERR_INVALID_CHARS,
                            value.data(),
                            static_cast<int>(value.size()),
                            result.data(),
                            count) != count) {
        return std::nullopt;
    }
    return result;
}

std::optional<std::string> narrow_utf8(std::wstring_view value) {
    if (value.size() > static_cast<std::size_t>(INT_MAX)) {
        return std::nullopt;
    }
    const int count = WideCharToMultiByte(CP_UTF8,
                                          WC_ERR_INVALID_CHARS,
                                          value.data(),
                                          static_cast<int>(value.size()),
                                          nullptr,
                                          0,
                                          nullptr,
                                          nullptr);
    if (count <= 0) {
        return std::nullopt;
    }
    std::string result(static_cast<std::size_t>(count), '\0');
    if (WideCharToMultiByte(CP_UTF8,
                            WC_ERR_INVALID_CHARS,
                            value.data(),
                            static_cast<int>(value.size()),
                            result.data(),
                            count,
                            nullptr,
                            nullptr) != count) {
        return std::nullopt;
    }
    return result;
}

std::expected<std::string, std::string>
winhttp_location(std::string_view url,
                 std::size_t maximum_bytes,
                 const std::filesystem::path& destination,
                 int& status) {
    const auto wide_url = widen_ascii(url);
    if (!wide_url) {
        return std::unexpected("invalid HTTPS URL");
    }
    URL_COMPONENTSW components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(wide_url->c_str(), 0, 0, &components) ||
        components.nScheme != INTERNET_SCHEME_HTTPS ||
        components.nPort != INTERNET_DEFAULT_HTTPS_PORT ||
        components.dwUserNameLength != 0 || components.dwPasswordLength != 0) {
        return std::unexpected("invalid HTTPS URL components");
    }
    const std::wstring host{components.lpszHostName,
                            components.dwHostNameLength};
    std::wstring target{components.lpszUrlPath, components.dwUrlPathLength};
    if (components.dwExtraInfoLength != 0) {
        target.append(components.lpszExtraInfo, components.dwExtraInfoLength);
    }
    InternetHandle session{WinHttpOpen(L"Kasumi updater/1.0",
                                       WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                       WINHTTP_NO_PROXY_NAME,
                                       WINHTTP_NO_PROXY_BYPASS,
                                       0)};
    if (!session.value) {
        return std::unexpected("WinHTTP initialization failed");
    }
    WinHttpSetTimeouts(session.value, 15000, 15000, 30000, 30000);
    InternetHandle connection{
        WinHttpConnect(session.value, host.c_str(), components.nPort, 0)};
    if (!connection.value) {
        return std::unexpected("could not connect to GitHub");
    }
    InternetHandle request{WinHttpOpenRequest(connection.value,
                                              L"GET",
                                              target.c_str(),
                                              nullptr,
                                              WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                                              WINHTTP_FLAG_SECURE)};
    if (!request.value) {
        return std::unexpected("could not create HTTPS request");
    }
    DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(request.value,
                          WINHTTP_OPTION_REDIRECT_POLICY,
                          &redirect_policy,
                          sizeof(redirect_policy))) {
        return std::unexpected("could not restrict HTTPS redirects");
    }
    if (!WinHttpSendRequest(request.value,
                            WINHTTP_NO_ADDITIONAL_HEADERS,
                            0,
                            WINHTTP_NO_REQUEST_DATA,
                            0,
                            0,
                            0) ||
        !WinHttpReceiveResponse(request.value, nullptr)) {
        return std::unexpected("HTTPS request failed");
    }
    DWORD status_size = sizeof(status);
    if (!WinHttpQueryHeaders(request.value,
                             WINHTTP_QUERY_STATUS_CODE |
                                 WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX,
                             &status,
                             &status_size,
                             WINHTTP_NO_HEADER_INDEX)) {
        return std::unexpected("could not read HTTPS response status");
    }
    if (status >= 300 && status < 400) {
        DWORD location_size = 0;
        WinHttpQueryHeaders(request.value,
                            WINHTTP_QUERY_LOCATION,
                            WINHTTP_HEADER_NAME_BY_INDEX,
                            nullptr,
                            &location_size,
                            WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || location_size == 0 ||
            location_size > 64U * 1024U) {
            return std::unexpected("HTTPS redirect has no valid Location");
        }
        std::wstring location(location_size / sizeof(wchar_t), L'\0');
        if (!WinHttpQueryHeaders(request.value,
                                 WINHTTP_QUERY_LOCATION,
                                 WINHTTP_HEADER_NAME_BY_INDEX,
                                 location.data(),
                                 &location_size,
                                 WINHTTP_NO_HEADER_INDEX)) {
            return std::unexpected("could not read HTTPS redirect");
        }
        location.resize((location_size / sizeof(wchar_t)) - 1);
        auto value = narrow_utf8(location);
        if (!value) {
            return std::unexpected("invalid HTTPS redirect URL");
        }
        return *value;
    }
    if (status != 200) {
        return std::unexpected("GitHub returned HTTP " +
                               std::to_string(status));
    }
    std::ofstream output(destination, std::ios::binary | std::ios::trunc);
    if (!output) {
        return std::unexpected("could not create download file");
    }
    std::array<char, 16384> buffer{};
    std::size_t total = 0;
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.value, &available)) {
            return std::unexpected("could not read HTTPS response");
        }
        if (available == 0) {
            break;
        }
        const DWORD to_read =
            std::min<DWORD>(available, static_cast<DWORD>(buffer.size()));
        DWORD read = 0;
        if (!WinHttpReadData(request.value, buffer.data(), to_read, &read)) {
            return std::unexpected("HTTPS download was interrupted");
        }
        if (read == 0) {
            break;
        }
        if (read > maximum_bytes - std::min(maximum_bytes, total)) {
            return std::unexpected("download exceeds the permitted size");
        }
        output.write(buffer.data(), static_cast<std::streamsize>(read));
        if (!output) {
            return std::unexpected("could not write download file");
        }
        total += read;
    }
    output.close();
    if (!output) {
        return std::unexpected("could not finish download file");
    }
    return std::string{};
}

std::expected<void, std::string>
download_url(std::string url,
             const std::filesystem::path& destination,
             std::size_t maximum_bytes,
             bool api_request) {
    return https_with_redirects(
        std::move(url),
        api_request,
        [&](const std::string& current_url,
            std::string& next_url,
            bool& is_redirect) -> std::expected<void, std::string> {
            int status = 0;
            auto result = winhttp_location(
                current_url, maximum_bytes, destination, status);
            if (!result) {
                std::error_code ignored;
                std::filesystem::remove(destination, ignored);
                return std::unexpected(result.error());
            }
            if (!result->empty()) {
                next_url = std::move(*result);
                is_redirect = true;
            }
            return {};
        });
}

#else

std::expected<void, std::string>
download_url(std::string url,
             const std::filesystem::path& destination,
             std::size_t maximum_bytes,
             bool api_request,
             const platform::Workspace& /*workspace*/) {
    return https_with_redirects(
        std::move(url),
        api_request,
        [&](const std::string& current_url,
            std::string& next_url,
            bool& is_redirect) -> std::expected<void, std::string> {
            std::error_code ignored;
            std::filesystem::remove(destination, ignored);
            auto arguments =
                base_curl_args("curl", maximum_bytes, api_request ? 30 : 180);
            arguments.insert(arguments.end(),
                             {"--output",
                              platform::path::to_utf8(destination),
                              "--write-out",
                              "%{http_code}\n%{redirect_url}",
                              current_url});
            auto response = run_capture(arguments);
            if (!response || response->exit_code != 0) {
                std::filesystem::remove(destination, ignored);
                return std::unexpected(response
                                           ? (response->error_output.empty()
                                                  ? "HTTPS download failed"
                                                  : response->error_output)
                                           : response.error());
            }
            auto parsed = parse_curl_write_out(response->output, false);
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            if (parsed->status >= 300 && parsed->status < 400) {
                next_url = std::move(parsed->redirect_url);
                is_redirect = true;
                return {};
            }
            if (parsed->status != 200) {
                std::filesystem::remove(destination, ignored);
                return std::unexpected("GitHub returned HTTP " +
                                       std::to_string(parsed->status));
            }
            auto body = read_limited_file(destination, maximum_bytes);
            if (!body) {
                std::filesystem::remove(destination, ignored);
                return std::unexpected(body.error());
            }
            return {};
        });
}

#endif

std::expected<std::string, std::string>
get_text(std::string url,
         std::size_t maximum_bytes,
         const platform::Workspace& workspace) {
    const auto path = platform::workspace_file(workspace, "api-response.json");
    if (path.empty()) {
        return std::unexpected("could not allocate API response file");
    }
#if defined(_WIN32)
    auto downloaded = download_url(std::move(url), path, maximum_bytes, true);
#else
    auto downloaded =
        download_url(std::move(url), path, maximum_bytes, true, workspace);
#endif
    if (!downloaded) {
        return std::unexpected(downloaded.error());
    }
    auto response = read_limited_file(path, maximum_bytes);
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    return response;
}

std::expected<void, std::string>
download_asset(std::string url,
               const std::filesystem::path& destination,
               std::size_t maximum_bytes,
               const platform::Workspace& workspace) {
#if defined(_WIN32)
    (void)workspace;
    return download_url(std::move(url), destination, maximum_bytes, false);
#else
    return download_url(
        std::move(url), destination, maximum_bytes, false, workspace);
#endif
}

std::optional<std::filesystem::path>
resolve_regular_executable(const std::filesystem::path& candidate) {
    std::error_code error;
    auto resolved = std::filesystem::canonical(candidate, error);
    if (error || !std::filesystem::is_regular_file(resolved, error) || error) {
        return std::nullopt;
    }
    return resolved;
}

} // namespace

std::optional<std::filesystem::path> current_executable_path() {
#if defined(_WIN32)
    std::vector<wchar_t> buffer(1024);
    for (;;) {
        const DWORD length = GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            return std::nullopt;
        }
        if (length < buffer.size() - 1) {
            return resolve_regular_executable(std::filesystem::path{
                std::wstring_view{buffer.data(), length}});
        }
        if (buffer.size() >= 32768) {
            return std::nullopt;
        }
        buffer.resize(std::min<std::size_t>(buffer.size() * 2, 32768));
    }
#else
    std::vector<char> buffer(1024);
    for (;;) {
        const auto length =
            ::readlink("/proc/self/exe", buffer.data(), buffer.size());
        if (length < 0) {
            return std::nullopt;
        }
        if (static_cast<std::size_t>(length) < buffer.size()) {
            return resolve_regular_executable(
                std::filesystem::path{std::string_view{
                    buffer.data(), static_cast<std::size_t>(length)}});
        }
        if (buffer.size() >= 65536) {
            return std::nullopt;
        }
        buffer.resize(std::min<std::size_t>(buffer.size() * 2, 65536));
    }
#endif
}

namespace {

bool package_managed_installation(const std::filesystem::path& executable,
                                  std::string& manager) {
#if defined(_WIN32)
    auto path = lower_ascii(platform::path::to_utf8(executable));
    for (const auto marker : {"\\windowsapps\\",
                              "\\scoop\\apps\\",
                              "\\chocolatey\\lib\\",
                              "\\winget\\packages\\"}) {
        if (path.find(marker) != std::string::npos) {
            const auto value = std::string_view{marker};
            manager =
                value == "\\windowsapps\\"
                    ? "Microsoft Store"
                    : (value == "\\scoop\\apps\\"
                           ? "Scoop"
                           : (value == "\\winget\\packages\\" ? "WinGet"
                                                              : "Chocolatey"));
            return true;
        }
    }
    return false;
#else
    const auto path = lower_ascii(platform::path::to_utf8(executable));
    for (const auto& [marker, name] :
         {std::pair{std::string_view{"/snap/"}, std::string_view{"Snap"}},
          std::pair{std::string_view{"/nix/store/"}, std::string_view{"Nix"}},
          std::pair{std::string_view{"/var/lib/flatpak/"},
                    std::string_view{"Flatpak"}}}) {
        if (path.find(marker) != std::string::npos) {
            manager = name;
            return true;
        }
    }
    for (const auto* command : {"dpkg-query", "rpm"}) {
        const auto result =
            run_capture({command,
                         command == std::string_view{"rpm"} ? "-qf" : "-S",
                         platform::path::to_utf8(executable)},
                        4096,
                        4096);
        if (result && result->exit_code == 0) {
            manager = command == std::string_view{"rpm"} ? "RPM" : "dpkg";
            return true;
        }
    }
    for (const auto& command :
         {std::vector<std::string>{"pacman", "-Qo"},
          std::vector<std::string>{"apk", "info", "--who-owns"}}) {
        auto arguments = command;
        arguments.push_back(platform::path::to_utf8(executable));
        const auto result = run_capture(arguments, 4096, 4096);
        if (result && result->exit_code == 0) {
            manager = command.front() == "pacman" ? "Pacman" : "APK";
            return true;
        }
    }
    return false;
#endif
}

std::expected<std::string, std::string>
extract_and_validate(const std::filesystem::path& archive,
                     const PackageNames& package,
                     const std::filesystem::path& destination) {
    const auto archive_utf8 = platform::path::to_utf8(archive);
#if defined(_WIN32)
    const auto listing = run_capture({"tar", "-tvf", archive_utf8});
#else
    const auto listing = run_capture({"tar", "-tvzf", archive_utf8});
#endif
    if (!listing || listing->exit_code != 0) {
        return std::unexpected(listing ? "package archive is invalid"
                                       : listing.error());
    }
    if (!valid_verbose_archive_listing(listing->output, package)) {
        return std::unexpected("package contains unexpected or unsafe entries");
    }
    std::error_code error;
    if (!std::filesystem::create_directory(destination, error) || error) {
        return std::unexpected("could not create package extraction directory");
    }
    std::vector<std::string> extract_args{"tar",
#if defined(_WIN32)
                                          "-xf",
#else
                                          "-xzf",
#endif
                                          archive_utf8,
                                          "-C",
                                          platform::path::to_utf8(destination),
#if !defined(_WIN32)
                                          "--no-same-owner",
                                          "--no-same-permissions",
#endif
                                          "--",
                                          package.executable,
                                          "LICENSE",
                                          "THIRD_PARTY_NOTICES.md"};
    const auto extracted = run_capture(extract_args);
    if (!extracted || extracted->exit_code != 0) {
        return std::unexpected(extracted ? "could not extract verified package"
                                         : extracted.error());
    }
    for (const auto name : {std::string_view{package.executable},
                            std::string_view{"LICENSE"},
                            std::string_view{"THIRD_PARTY_NOTICES.md"}}) {
        const auto file = destination / platform::path::from_utf8(name);
        const auto status = std::filesystem::symlink_status(file, error);
        if (error || std::filesystem::is_symlink(status) ||
            !std::filesystem::is_regular_file(status)) {
            return std::unexpected("package entry is not a regular file");
        }
        const auto size = std::filesystem::file_size(file, error);
        const auto limit = name == package.executable ? EXECUTABLE_LIMIT
                                                      : PACKAGE_DOCUMENT_LIMIT;
        if (error || size == 0 || size > limit) {
            return std::unexpected("package entry has an invalid size");
        }
    }
    return platform::path::to_utf8(
        destination / platform::path::from_utf8(package.executable));
}

std::expected<void, std::string>
validate_executable_format(const std::filesystem::path& executable) {
    std::array<unsigned char, 64> header{};
#if defined(_WIN32)
    const auto handle =
        CreateFileW(executable.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return std::unexpected("package executable is incomplete");
    }
    struct HandleGuard {
        HANDLE h;
        ~HandleGuard() noexcept {
            CloseHandle(h);
        }
    } guard{handle};
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    LARGE_INTEGER size{};
    if (!GetFileInformationByHandleEx(
            handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes &
         (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY |
          FILE_ATTRIBUTE_DEVICE)) != 0 ||
        !GetFileSizeEx(handle, &size) || size.QuadPart < 256 ||
        static_cast<std::uint64_t>(size.QuadPart) > EXECUTABLE_LIMIT) {
        return std::unexpected("package is not a Windows executable");
    }
    DWORD read_count = 0;
    if (!ReadFile(handle,
                  header.data(),
                  static_cast<DWORD>(header.size()),
                  &read_count,
                  nullptr) ||
        read_count != header.size()) {
        return std::unexpected("package executable is incomplete");
    }
    if (header[0] != 'M' || header[1] != 'Z') {
        return std::unexpected("package is not a Windows executable");
    }
    std::uint32_t pe_offset = 0;
    std::memcpy(&pe_offset, header.data() + 0x3c, sizeof(pe_offset));
    std::array<unsigned char, 6> pe_header{};
    LARGE_INTEGER distance{};
    distance.QuadPart = static_cast<LONGLONG>(pe_offset);
    if (pe_offset >
            static_cast<std::uint64_t>(size.QuadPart) - pe_header.size() ||
        !SetFilePointerEx(handle, distance, nullptr, FILE_BEGIN) ||
        !ReadFile(handle,
                  pe_header.data(),
                  static_cast<DWORD>(pe_header.size()),
                  &read_count,
                  nullptr) ||
        read_count != pe_header.size()) {
        return std::unexpected("package is not a Windows executable");
    }
    if (std::memcmp(pe_header.data(), "PE\0\0", 4) != 0 ||
        pe_header[4] != 0x64 || pe_header[5] != 0x86) {
        return std::unexpected("package executable is not x86_64 Windows");
    }
#else
    const int fd =
        ::open(executable.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return std::unexpected("package executable is incomplete");
    }
    struct FdGuard {
        int fd;
        ~FdGuard() noexcept {
            ::close(fd);
        }
    } guard{fd};
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 64 ||
        static_cast<std::uint64_t>(st.st_size) > EXECUTABLE_LIMIT) {
        return std::unexpected("package executable is incomplete");
    }
    std::size_t filled = 0;
    while (filled < header.size()) {
        const auto count =
            ::read(fd, header.data() + filled, header.size() - filled);
        if (count == 0) {
            return std::unexpected("package executable is incomplete");
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected("package executable is incomplete");
        }
        filled += static_cast<std::size_t>(count);
    }
    if (header[0] != 0x7f || header[1] != 'E' || header[2] != 'L' ||
        header[3] != 'F' || header[4] != 2 || header[5] != 1 ||
        header[18] != 62) {
        return std::unexpected("package executable is not x86_64 Linux");
    }
#endif
    return {};
}

std::expected<PreparedExecutable, std::string>
prepare_verified_package(const std::filesystem::path& archive,
                         std::string_view expected_hash,
                         const PackageNames& package,
                         const platform::Workspace& workspace) {
    const auto actual_hash = sha256_file(archive);
    if (!actual_hash ||
        lower_ascii(*actual_hash) != lower_ascii(expected_hash)) {
        return std::unexpected(actual_hash ? "package SHA-256 does not match"
                                           : actual_hash.error());
    }
    const auto extraction = platform::workspace_file(workspace, "extracted");
    if (extraction.empty()) {
        return std::unexpected("could not allocate package extraction path");
    }
    auto executable = extract_and_validate(archive, package, extraction);
    if (!executable) {
        return std::unexpected(executable.error());
    }
    auto format =
        validate_executable_format(platform::path::from_utf8(*executable));
    if (!format) {
        return std::unexpected(format.error());
    }
    const auto executable_path = platform::path::from_utf8(*executable);
    const auto executable_hash = sha256_file(executable_path);
    if (!executable_hash) {
        return std::unexpected(executable_hash.error());
    }
    return PreparedExecutable{.path = executable_path,
                              .sha256 = *executable_hash,
                              .workspace = workspace};
}

} // namespace

std::expected<std::string, std::string>
sha256_file(const std::filesystem::path& path) {
    return crypto::physical::hash_file(path, "sha256");
}

std::optional<Version> parse_version(std::string_view text) {
    if (text.starts_with('v')) {
        text.remove_prefix(1);
    }
    if (text.empty()) {
        return std::nullopt;
    }
    const auto plus = text.find('+');
    const auto core_and_pre = text.substr(0, plus);
    if (plus != std::string_view::npos) {
        const auto build = text.substr(plus + 1);
        for (const auto identifier : split(build, '.')) {
            if (!valid_identifier(identifier, true)) {
                return std::nullopt;
            }
        }
    }
    const auto dash = core_and_pre.find('-');
    const auto core = core_and_pre.substr(0, dash);
    const auto core_parts = split(core, '.');
    if (core_parts.size() != 3) {
        return std::nullopt;
    }
    Version result;
    const auto parse_number = [](std::string_view input,
                                 unsigned long long& value) {
        if (input.empty() || (input.size() > 1 && input.front() == '0') ||
            !std::ranges::all_of(input, [](char character) {
                return character >= '0' && character <= '9';
            })) {
            return false;
        }
        const auto [end, error] =
            std::from_chars(input.data(), input.data() + input.size(), value);
        return error == std::errc{} && end == input.data() + input.size();
    };
    if (!parse_number(core_parts[0], result.major) ||
        !parse_number(core_parts[1], result.minor) ||
        !parse_number(core_parts[2], result.patch)) {
        return std::nullopt;
    }
    if (dash != std::string_view::npos) {
        for (const auto identifier :
             split(core_and_pre.substr(dash + 1), '.')) {
            if (!valid_identifier(identifier, false)) {
                return std::nullopt;
            }
            result.prerelease.emplace_back(identifier);
        }
    }
    result.text = std::string{text};
    return result;
}

std::strong_ordering compare_versions(const Version& left,
                                      const Version& right) noexcept {
    if (const auto core = std::tie(left.major, left.minor, left.patch) <=>
                          std::tie(right.major, right.minor, right.patch);
        core != 0) {
        return core;
    }
    if (left.prerelease.empty() != right.prerelease.empty()) {
        return left.prerelease.empty() ? std::strong_ordering::greater
                                       : std::strong_ordering::less;
    }
    for (std::size_t index = 0;
         index < std::min(left.prerelease.size(), right.prerelease.size());
         ++index) {
        if (const auto compared = compare_identifier(left.prerelease[index],
                                                     right.prerelease[index]);
            compared != 0) {
            return compared;
        }
    }
    return left.prerelease.size() <=> right.prerelease.size();
}

std::optional<std::size_t>
select_release_index(std::span<const Release> releases) {
    std::vector<std::optional<Version>> versions;
    versions.reserve(releases.size());
    bool stable_channel_exists = false;
    for (const auto& release : releases) {
        auto version = release.tag.starts_with('v') ? parse_version(release.tag)
                                                    : std::nullopt;
        if (version && !release.draft && !release.prerelease &&
            version->prerelease.empty() && version->major >= 1) {
            stable_channel_exists = true;
        }
        versions.push_back(std::move(version));
    }
    std::optional<std::size_t> selected;
    for (std::size_t index = 0; index < releases.size(); ++index) {
        if (releases[index].draft || !versions[index]) {
            continue;
        }
        const auto& version = *versions[index];
        if (stable_channel_exists) {
            if (releases[index].prerelease || !version.prerelease.empty() ||
                version.major < 1) {
                continue;
            }
        } else if (version.major != 0) {
            continue;
        }
        if (!selected || compare_versions(version, *versions[*selected]) > 0 ||
            (compare_versions(version, *versions[*selected]) == 0 &&
             releases[index].tag > releases[*selected].tag)) {
            selected = index;
        }
    }
    return selected;
}

bool installed_version_is_current_or_newer(std::string_view current,
                                           const Version& latest) {
    const auto installed = parse_version(current);
    return installed && compare_versions(*installed, latest) >= 0;
}

std::expected<std::vector<Release>, std::string>
parse_releases_json(std::string_view body) {
    Json value;
    try {
        value = Json::parse(body);
    } catch (const Json::exception&) {
        return std::unexpected("GitHub returned invalid release JSON");
    }
    if (!value.is_array()) {
        return std::unexpected("GitHub release response is not an array");
    }
    std::vector<Release> releases;
    releases.reserve(value.size());
    for (const auto& entry : value) {
        if (!entry.is_object() || !entry.contains("tag_name") ||
            !entry["tag_name"].is_string() || !entry.contains("draft") ||
            !entry["draft"].is_boolean() || !entry.contains("prerelease") ||
            !entry["prerelease"].is_boolean() || !entry.contains("assets") ||
            !entry["assets"].is_array()) {
            return std::unexpected(
                "GitHub release response has an invalid shape");
        }
        Release release{.tag = entry["tag_name"].get<std::string>(),
                        .draft = entry["draft"].get<bool>(),
                        .prerelease = entry["prerelease"].get<bool>()};
        for (const auto& asset : entry["assets"]) {
            if (!asset.is_object() || !asset.contains("name") ||
                !asset["name"].is_string() ||
                !asset.contains("browser_download_url") ||
                !asset["browser_download_url"].is_string()) {
                return std::unexpected(
                    "GitHub asset response has an invalid shape");
            }
            release.assets.push_back(
                Asset{.name = asset["name"].get<std::string>(),
                      .url = asset["browser_download_url"].get<std::string>()});
        }
        releases.push_back(std::move(release));
    }
    return releases;
}

std::expected<std::vector<Release>, std::string>
fetch_releases(const ApiGet& get) {
    if (!get) {
        return std::unexpected("GitHub API request is unavailable");
    }
    constexpr std::size_t per_page = 100;
    constexpr std::size_t maximum_pages = 20;
    std::vector<Release> releases;
    for (std::size_t page = 1; page <= maximum_pages; ++page) {
        const auto url = std::format(
            "https://api.github.com/repos/{}/releases?per_page=100&page={}",
            GITHUB_REPOSITORY,
            page);
        auto response = get(url, API_RESPONSE_LIMIT);
        if (!response) {
            return std::unexpected(response.error());
        }
        if (response->status != 200 ||
            response->body.size() > API_RESPONSE_LIMIT) {
            return std::unexpected("GitHub releases request failed with HTTP " +
                                   std::to_string(response->status));
        }
        auto page_releases = parse_releases_json(response->body);
        if (!page_releases) {
            return std::unexpected(page_releases.error());
        }
        const auto count = page_releases->size();
        releases.insert(releases.end(),
                        std::make_move_iterator(page_releases->begin()),
                        std::make_move_iterator(page_releases->end()));
        if (count < per_page) {
            return releases;
        }
    }
    return std::unexpected(
        "GitHub has more releases than the updater will scan");
}

std::optional<PackageNames> package_names_for_this_platform() {
#if defined(_WIN32)
#if defined(_M_X64) || defined(__x86_64__)
    return PackageNames{"kasumi-windows-x86_64.zip",
                        "kasumi-windows-x86_64.zip.sha256",
                        "kasumi.exe"};
#else
    return std::nullopt;
#endif
#elif defined(__linux__) && defined(__x86_64__)
    return PackageNames{"kasumi-linux-x86_64.tar.gz",
                        "kasumi-linux-x86_64.tar.gz.sha256",
                        "kasumi"};
#else
    return std::nullopt;
#endif
}

std::optional<std::string> parse_checksum(std::string_view body,
                                          std::string_view expected_name) {
    while (!body.empty() && (body.back() == '\n' || body.back() == '\r')) {
        body.remove_suffix(1);
    }
    if (body.find_first_of("\r\n") != std::string_view::npos ||
        body.size() < 64 || !valid_sha256(body.substr(0, 64))) {
        return std::nullopt;
    }
    const auto digest = body.substr(0, 64);
    const auto suffix = body.substr(64);
    if (!suffix.empty()) {
        std::string_view filename;
        if (suffix.starts_with("  ")) {
            filename = suffix.substr(2);
        } else if (suffix.starts_with(" *")) {
            filename = suffix.substr(2);
        } else if (suffix.starts_with(' ')) {
            filename = suffix.substr(1);
        } else {
            return std::nullopt;
        }
        if (filename != expected_name) {
            return std::nullopt;
        }
    }
    return lower_ascii(digest);
}

bool valid_verbose_archive_listing(std::string_view listing,
                                   const PackageNames& package) {
    const std::set<std::string_view> required{
        package.executable, "LICENSE", "THIRD_PARTY_NOTICES.md"};
    const std::set<std::string_view> optional{"CHANGELOG.md", "README.md"};
    std::set<std::string_view> found;
    std::size_t begin = 0;
    while (begin < listing.size()) {
        auto end = listing.find('\n', begin);
        if (end == std::string_view::npos) {
            end = listing.size();
        }
        auto line = listing.substr(begin, end - begin);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        if (line.empty() || line.front() != '-') {
            return false;
        }
        const auto name_separator = line.find_last_of(" \t");
        if (name_separator == std::string_view::npos ||
            name_separator + 1 == line.size()) {
            return false;
        }
        const auto name = line.substr(name_separator + 1);
        if ((!required.contains(name) && !optional.contains(name)) ||
            !found.insert(name).second) {
            return false;
        }
        std::istringstream fields{std::string{line.substr(0, name_separator)}};
        std::vector<std::string> tokens;
        std::string token;
        while (fields >> token) {
            tokens.push_back(token);
        }
        if (tokens.size() < 3) {
            return false;
        }
        const auto size_index =
            tokens.size() >= 5 && tokens[1] == "0" && tokens[2] == "0" &&
                    tokens[3] == "0"
                ? 4U
                : (tokens.size() >= 4 && tokens[1] == "0" && tokens[2] == "0"
                       ? 3U
                       : 2U);
        if (size_index >= tokens.size()) {
            return false;
        }
        std::uint64_t size = 0;
        const auto [size_end, size_error] = std::from_chars(
            tokens[size_index].data(),
            tokens[size_index].data() + tokens[size_index].size(),
            size);
        const auto limit = name == package.executable ? EXECUTABLE_LIMIT
                                                      : PACKAGE_DOCUMENT_LIMIT;
        if (size_error != std::errc{} ||
            size_end != tokens[size_index].data() + tokens[size_index].size() ||
            size == 0 || size > limit) {
            return false;
        }
        if (end == listing.size()) {
            break;
        }
        begin = end + 1;
    }
    return std::ranges::all_of(required, [&found](std::string_view entry) {
        return found.contains(entry);
    });
}

std::string make_official_asset_url(std::string_view tag,
                                    std::string_view name) {
    return std::format("https://github.com/{}/releases/download/{}/{}",
                       GITHUB_REPOSITORY,
                       tag,
                       name);
}

bool official_asset_url(std::string_view tag,
                        std::string_view name,
                        std::string_view url) {
    if (!tag.starts_with('v') || !parse_version(tag) || name.empty() ||
        name.find_first_of("/\\?#\r\n") != std::string_view::npos) {
        return false;
    }
    return url == make_official_asset_url(tag, name);
}

namespace {

bool is_regular_file_without_redirect(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    return !error && std::filesystem::is_regular_file(status) &&
           !std::filesystem::is_symlink(status);
}

InstallFailure
install_failure(std::string detail,
                InstallFailure::Kind kind = InstallFailure::Kind::Other) {
    return InstallFailure{.kind = kind, .detail = std::move(detail)};
}

InstallFailure filesystem_failure(std::string_view operation,
                                  const std::error_code& error) {
    const auto kind = error == std::errc::permission_denied ||
                              error == std::errc::operation_not_permitted
                          ? InstallFailure::Kind::PermissionDenied
                          : InstallFailure::Kind::Other;
    return install_failure(std::string{operation} + ": " + error.message(),
                           kind);
}

InstallFailure replacement_failure(std::string detail) {
    constexpr std::string_view marker = "native_code=";
    const auto offset = detail.find(marker);
    if (offset != std::string::npos) {
        unsigned long code = 0;
        const auto begin = detail.data() + offset + marker.size();
        const auto end = detail.data() + detail.size();
        const auto [parsed, error] = std::from_chars(begin, end, code);
        if (error == std::errc{} && parsed != begin) {
#if defined(_WIN32)
            if (code == ERROR_ACCESS_DENIED ||
                code == ERROR_PRIVILEGE_NOT_HELD) {
                return install_failure(std::move(detail),
                                       InstallFailure::Kind::PermissionDenied);
            }
#else
            if (code == EACCES || code == EPERM) {
                return install_failure(std::move(detail),
                                       InstallFailure::Kind::PermissionDenied);
            }
#endif
        }
    }
    return install_failure(std::move(detail));
}

#if !defined(_WIN32)
std::expected<void, InstallFailure>
preserve_posix_attributes(const std::filesystem::path& path,
                          const struct stat& original_stat,
                          std::string_view inspect_error,
                          std::string_view ownership_error,
                          std::string_view permission_error) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return std::unexpected(filesystem_failure(
            inspect_error, std::error_code{errno, std::generic_category()}));
    }
    platform::private_storage::PrivateHandle guard{fd};
    struct stat entry_stat{};
    if (::fstat(fd, &entry_stat) != 0 || !S_ISREG(entry_stat.st_mode)) {
        return std::unexpected(filesystem_failure(
            inspect_error, std::error_code{errno, std::generic_category()}));
    }
    if ((entry_stat.st_uid != original_stat.st_uid ||
         entry_stat.st_gid != original_stat.st_gid) &&
        ::fchown(fd,
                 entry_stat.st_uid == original_stat.st_uid
                     ? static_cast<uid_t>(-1)
                     : original_stat.st_uid,
                 entry_stat.st_gid == original_stat.st_gid
                     ? static_cast<gid_t>(-1)
                     : original_stat.st_gid) != 0) {
        return std::unexpected(filesystem_failure(
            ownership_error, std::error_code{errno, std::generic_category()}));
    }
    if (::fchmod(fd, original_stat.st_mode & 07777) != 0) {
        return std::unexpected(filesystem_failure(
            permission_error, std::error_code{errno, std::generic_category()}));
    }
    return {};
}
#endif

} // namespace

InstallResult install_prepared_executable(const std::filesystem::path& prepared,
                                          const std::filesystem::path& target,
                                          std::string_view expected_sha256,
                                          const InstallHooks* hooks) {
    const auto validate_target = hooks != nullptr && hooks->validate_target
                                     ? hooks->validate_target
                                     : [](const std::filesystem::path&)
        -> std::expected<void, std::string> {
        return {};
    };
    if (const auto valid = validate_target(target); !valid) {
        return std::unexpected(install_failure(valid.error()));
    }
    if (!valid_sha256(expected_sha256)) {
        return std::unexpected(
            install_failure("expected executable digest is invalid"));
    }
    if (!is_regular_file_without_redirect(prepared) ||
        !is_regular_file_without_redirect(target)) {
        return std::unexpected(install_failure(
            "installer requires regular source and target files"));
    }
    std::error_code error;
    const auto parent_status =
        std::filesystem::symlink_status(target.parent_path(), error);
    if (error || std::filesystem::is_symlink(parent_status) ||
        !std::filesystem::is_directory(parent_status)) {
        return std::unexpected(install_failure(
            "installation directory cannot be identified safely"));
    }
    const auto hash_file = hooks != nullptr && hooks->hash_file
                               ? hooks->hash_file
                               : [](const std::filesystem::path& path) {
                                     return sha256_file(path);
                                 };
    const auto replace =
        hooks != nullptr && hooks->replace_atomically
            ? hooks->replace_atomically
            : [](const std::filesystem::path& source,
                 const std::filesystem::path& destination) {
                  return platform::durability::replace_atomically(source,
                                                                  destination);
              };
    const auto prepared_hash = hash_file(prepared);
    if (!prepared_hash) {
        return std::unexpected(install_failure(prepared_hash.error()));
    }
    if (lower_ascii(*prepared_hash) != lower_ascii(expected_sha256)) {
        return std::unexpected(install_failure(
            "prepared executable changed after package verification"));
    }
    const auto original_hash = hash_file(target);
    if (!original_hash) {
        return std::unexpected(install_failure(original_hash.error()));
    }
    auto id = platform::random::hex_id();
    if (!id) {
        return std::unexpected(install_failure(id.error()));
    }
    const auto staged = target.parent_path() /
                        platform::path::from_utf8(".kasumi-update-" + *id);
    const auto backup = target.parent_path() /
                        platform::path::from_utf8(".kasumi-previous-" + *id);
    struct TemporaryFiles {
        std::filesystem::path staged;
        std::filesystem::path backup;
        bool preserve_backup = false;
        ~TemporaryFiles() {
            std::error_code ignored;
            std::filesystem::remove(staged, ignored);
            if (!preserve_backup) {
                std::filesystem::remove(backup, ignored);
            }
        }
    } files{.staged = staged, .backup = backup};
#if !defined(_WIN32)
    struct stat original_stat{};
    if (::lstat(target.c_str(), &original_stat) != 0 ||
        !S_ISREG(original_stat.st_mode)) {
        return std::unexpected(filesystem_failure(
            "could not inspect executable ownership",
            std::error_code{errno, std::generic_category()}));
    }
#endif
    const auto prepare_copy =
        [&](const std::filesystem::path& source,
            const std::filesystem::path& destination,
            std::string_view expected_digest,
            std::string_view copy_error,
            std::string_view attr_label,
            std::string_view mismatch_error) -> InstallResult {
        std::error_code copy_ec;
        if (!std::filesystem::copy_file(source,
                                        destination,
                                        std::filesystem::copy_options::none,
                                        copy_ec) ||
            copy_ec) {
            return std::unexpected(filesystem_failure(copy_error, copy_ec));
        }
#if !defined(_WIN32)
        if (const auto preserved = preserve_posix_attributes(
                destination,
                original_stat,
                "could not inspect " + std::string{attr_label} + " ownership",
                "could not preserve " + std::string{attr_label} + " ownership",
                "could not preserve " + std::string{attr_label} +
                    " permissions");
            !preserved) {
            return std::unexpected(preserved.error());
        }
#endif
        const auto copy_hash = hash_file(destination);
        if (!copy_hash ||
            lower_ascii(*copy_hash) != lower_ascii(expected_digest)) {
            return std::unexpected(install_failure(
                copy_hash ? std::string{mismatch_error} : copy_hash.error()));
        }
        if (const auto synced = platform::durability::sync_file(destination);
            !synced) {
            return std::unexpected(install_failure(synced.error()));
        }
        return {};
    };
    if (const auto ok =
            prepare_copy(prepared,
                         staged,
                         expected_sha256,
                         "could not prepare executable beside installation",
                         "executable",
                         "staged executable changed before replacement");
        !ok) {
        return ok;
    }
    if (const auto ok = prepare_copy(
            target,
            backup,
            *original_hash,
            "could not keep a recovery copy of the installed executable",
            "recovery copy",
            "recovery copy does not match installed executable");
        !ok) {
        return ok;
    }
    if (const auto valid = validate_target(target); !valid) {
        return std::unexpected(install_failure(valid.error()));
    }
    auto replaced = replace(staged, target);
    if (!replaced) {
        return std::unexpected(replacement_failure(replaced.error()));
    }
    const auto new_status = std::filesystem::symlink_status(target, error);
    const auto installed_hash =
        error ? std::expected<std::string, std::string>{std::unexpected(
                    "target query failed")}
              : hash_file(target);
    if (error || std::filesystem::is_symlink(new_status) ||
        !std::filesystem::is_regular_file(new_status) || !installed_hash ||
        lower_ascii(*installed_hash) != lower_ascii(expected_sha256)) {
        const auto rollback = replace(backup, target);
        if (rollback) {
            files.preserve_backup = false;
            static_cast<void>(
                platform::durability::sync_parent_directory(target));
            return std::unexpected(
                install_failure("installed executable failed verification; "
                                "previous version restored"));
        }
        files.preserve_backup = true;
        return std::unexpected(install_failure(
            "installed executable failed verification; rollback failed, "
            "recovery copy remains at " +
            platform::path::to_utf8(backup) + ": " + rollback.error()));
    }
    if (const auto synced = platform::durability::sync_parent_directory(target);
        !synced) {
        files.preserve_backup = true;
        return std::unexpected(
            install_failure("executable was replaced but directory sync "
                            "failed; recovery copy remains at " +
                            platform::path::to_utf8(backup)));
    }
    files.preserve_backup = true;
    return {};
}

InstallResult install_once_then_elevate(const InstallAction& install,
                                        const InstallAction& elevate) {
    if (!install) {
        return std::unexpected(
            install_failure("installer action is unavailable"));
    }
    auto result = install();
    if (result ||
        result.error().kind != InstallFailure::Kind::PermissionDenied) {
        return result;
    }
    if (!elevate) {
        return result;
    }
    return elevate();
}

namespace {

#if defined(_WIN32)
struct WindowsWellKnownSid {
    alignas(DWORD) std::array<std::byte, SECURITY_MAX_SID_SIZE> data{};
    bool init(WELL_KNOWN_SID_TYPE type) noexcept {
        DWORD size = static_cast<DWORD>(data.size());
        return CreateWellKnownSid(type, nullptr, data.data(), &size) != 0;
    }
    PSID get() noexcept {
        return data.data();
    }
};

bool query_current_user_token(std::vector<std::byte>& token_data) {
    HANDLE raw_token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token) == 0) {
        return false;
    }
    const ScopedWindowsHandle token{raw_token};
    DWORD required = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &required);
    token_data.resize(required);
    return required != 0 && GetTokenInformation(token.value,
                                                TokenUser,
                                                token_data.data(),
                                                required,
                                                &required) != 0;
}

struct WindowsWorkspaceAcl {
    std::wstring path;
    LocalSecurityDescriptor descriptor;
    PACL dacl = nullptr;
    PSID owner = nullptr;
    bool protected_dacl = false;
    ACL_SIZE_INFORMATION info{};
};

std::expected<WindowsWorkspaceAcl, std::string>
query_windows_workspace_acl(const std::filesystem::path& root,
                            std::string_view read_error) {
    WindowsWorkspaceAcl acl{.path = root.native()};
    PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
    const auto query = GetNamedSecurityInfoW(acl.path.data(),
                                             SE_FILE_OBJECT,
                                             DACL_SECURITY_INFORMATION |
                                                 OWNER_SECURITY_INFORMATION,
                                             &acl.owner,
                                             nullptr,
                                             &acl.dacl,
                                             nullptr,
                                             &raw_descriptor);
    acl.descriptor.reset(raw_descriptor);
    if (query != ERROR_SUCCESS || !acl.descriptor || acl.dacl == nullptr) {
        return std::unexpected(std::string{read_error});
    }
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    acl.protected_dacl =
        GetSecurityDescriptorControl(
            acl.descriptor.get(), &control, &revision) != 0 &&
        (control & SE_DACL_PROTECTED) != 0 &&
        GetAclInformation(
            acl.dacl, &acl.info, sizeof(acl.info), AclSizeInformation) != 0;
    return acl;
}

bool windows_entry_is_not_reparse_point(const std::filesystem::path& path) {
    return windows_has_attribute_flags(
        path, FILE_FLAG_BACKUP_SEMANTICS, FILE_ATTRIBUTE_REPARSE_POINT);
}
#endif

#if defined(__linux__)
std::optional<uid_t> invoking_user_id() {
    const char* value = std::getenv("PKEXEC_UID");
    if (value == nullptr) {
        value = std::getenv("SUDO_UID");
    }
    if (value == nullptr || *value == '\0') {
        return std::nullopt;
    }
    uid_t result = 0;
    const auto end = value + std::char_traits<char>::length(value);
    const auto [parsed, error] = std::from_chars(value, end, result);
    if (error != std::errc{} || parsed != end || result == 0) {
        return std::nullopt;
    }
    return result;
}
#endif

std::expected<void, std::string>
validate_staging_root(const std::filesystem::path& root) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(root, error);
    if (error || !root.is_absolute() || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status) ||
        !root.filename().native().starts_with(
            platform::path::from_utf8("kasumi-update-").native())) {
        return std::unexpected("update staging directory is invalid");
    }
#if defined(_WIN32)
    if (!windows_entry_is_not_reparse_point(root)) {
        return std::unexpected(
            "update staging directory cannot be resolved safely");
    }
    return validate_windows_workspace_acl(root);
#else
    const auto canonical_root = std::filesystem::canonical(root, error);
    if (error || canonical_root != root) {
        return std::unexpected(
            "update staging directory cannot be resolved safely");
    }
    struct stat workspace_stat{};
    if (::stat(root.c_str(), &workspace_stat) != 0 ||
        (workspace_stat.st_mode & 0077) != 0) {
        return std::unexpected("update staging directory is not private");
    }
    if (workspace_stat.st_uid != ::getuid()) {
        if (::geteuid() != 0) {
            return std::unexpected(
                "update staging directory has an unexpected owner");
        }
#if defined(__linux__)
        const auto expected_uid = invoking_user_id();
        if (!expected_uid) {
            return std::unexpected("could not validate update staging owner");
        }
        if (workspace_stat.st_uid != *expected_uid) {
            return std::unexpected(
                "update staging directory has an unexpected owner");
        }
#else
        return std::unexpected("could not validate update staging owner");
#endif
    }
    return {};
#endif
}

#if defined(_WIN32)
std::expected<PreparedExecutable, std::string>
prepare_archive_for_install(const std::filesystem::path& archive,
                            std::string_view checksum,
                            const PackageNames& package,
                            std::string_view extraction_name) {
    const auto root = archive.parent_path();
    auto valid_root = validate_staging_root(root);
    if (!valid_root ||
        archive.filename() != platform::path::from_utf8(package.archive) ||
        !is_regular_file_without_redirect(archive)) {
        return std::unexpected(
            "update package is outside its private staging directory");
    }
    std::error_code error;
    const auto size = std::filesystem::file_size(archive, error);
    if (error || size == 0 || size > PACKAGE_LIMIT) {
        return std::unexpected("update package has an invalid size");
    }
    auto workspace = platform::create_workspace_at(
        root / platform::path::from_utf8(extraction_name));
    if (!workspace) {
        return std::unexpected(
            "could not create package verification directory: " +
            workspace.error());
    }
    auto prepared =
        prepare_verified_package(archive, checksum, package, *workspace);
    if (!prepared) {
        platform::cleanup_workspace(*workspace);
        return std::unexpected(prepared.error());
    }
    return *prepared;
}
#endif

ApiGet make_workspace_api_get(const platform::Workspace& workspace) {
    return [&](std::string_view url,
               std::size_t limit) -> std::expected<HttpResponse, std::string> {
        auto body = get_text(std::string{url}, limit, workspace);
        if (!body) {
            return std::unexpected(body.error());
        }
        return HttpResponse{.status = 200, .body = std::move(*body)};
    };
}

struct ScopedWorkspaceCleanup {
    platform::Workspace value;
    bool released = false;
    ~ScopedWorkspaceCleanup() {
        if (!released) {
            platform::cleanup_workspace(value);
        }
    }
};

std::optional<std::string> release_asset_url(const Release& release,
                                             std::string_view name) {
    const Asset* found = nullptr;
    for (const auto& asset : release.assets) {
        if (asset.name == name) {
            if (found != nullptr) {
                return std::nullopt;
            }
            found = &asset;
        }
    }
    if (found == nullptr ||
        !official_asset_url(release.tag, name, found->url)) {
        return std::nullopt;
    }
    return found->url;
}

#if defined(_WIN32)
std::expected<std::string, std::string>
refetch_official_digest(const std::filesystem::path& archive,
                        std::string_view requested_tag,
                        const PackageNames& package,
                        const platform::Workspace& workspace) {
    const auto current = parse_version(KASUMI_VERSION);
    if (!current) {
        return std::unexpected("installed version metadata is invalid");
    }
    const auto requested = parse_version(requested_tag);
    if (!requested ||
        installed_version_is_current_or_newer(current->text, *requested)) {
        return std::unexpected("installer handoff release is invalid or older");
    }
    auto releases = fetch_releases(make_workspace_api_get(workspace));
    if (!releases) {
        return std::unexpected(releases.error());
    }
    const auto selected = select_release_index(*releases);
    if (!selected || (*releases)[*selected].tag != requested_tag) {
        return std::unexpected(
            "official update release changed during handoff");
    }
    const auto checksum_url =
        release_asset_url((*releases)[*selected], package.checksum);
    if (!checksum_url ||
        archive.filename() != platform::path::from_utf8(package.archive)) {
        return std::unexpected("official release checksum is unavailable");
    }
    const auto checksum_file =
        platform::workspace_file(workspace, "privileged-package.sha256");
    if (checksum_file.empty()) {
        return std::unexpected("could not allocate privileged checksum path");
    }
    auto downloaded =
        download_asset(*checksum_url, checksum_file, 4096, workspace);
    if (!downloaded) {
        return std::unexpected(downloaded.error());
    }
    return verify_package_checksum(archive, checksum_file, package.archive);
}
#endif

#if defined(__linux__)
std::expected<HttpResponse, std::string>
curl_get_as_user_once(std::string_view url,
                      std::size_t max_bytes,
                      bool api_request,
                      uid_t uid,
                      std::string& redirect_url) {
    const auto curl = resolve_linux_system_tool("curl");
    if (!curl) {
        return std::unexpected(curl.error());
    }
    const auto* account = ::getpwuid(uid);
    if (uid == 0 || account == nullptr) {
        return std::unexpected("could not identify the original updater user");
    }
    const std::string username{account->pw_name};
    const std::string home{account->pw_dir};
    const gid_t gid = account->pw_gid;
    int group_count = 16;
    std::vector<gid_t> groups(static_cast<std::size_t>(group_count));
    for (;;) {
        int required = group_count;
        if (::getgrouplist(username.c_str(), gid, groups.data(), &required) >=
            0) {
            groups.resize(static_cast<std::size_t>(required));
            break;
        }
        if (required <= group_count || required > 256) {
            return std::unexpected(
                "could not read original updater user groups");
        }
        group_count = required;
        groups.resize(static_cast<std::size_t>(group_count));
    }
    auto argument_values = base_curl_args(curl->string(), max_bytes, 30);
    argument_values.insert(argument_values.end(),
                           {"--write-out",
                            "\n%{http_code}\n%{redirect_url}",
                            "--url",
                            std::string{url}});
    if (api_request) {
        argument_values.push_back("--header");
        argument_values.push_back("Accept: application/vnd.github+json");
        argument_values.push_back("--header");
        argument_values.push_back("User-Agent: kasumi-updater");
    }
    std::vector<char*> arguments;
    arguments.reserve(argument_values.size() + 1);
    for (auto& argument : argument_values) {
        arguments.push_back(argument.data());
    }
    arguments.push_back(nullptr);
    std::vector<std::string> environment{"HOME=" + home};
    for (const auto& [name, value] : linux_base_environment(true, true)) {
        environment.push_back(name + "=" + value);
    }
    std::vector<char*> environment_pointers;
    environment_pointers.reserve(environment.size() + 1);
    for (auto& value : environment) {
        environment_pointers.push_back(value.data());
    }
    environment_pointers.push_back(nullptr);
    int pipe_fds[2]{};
    if (::pipe2(pipe_fds, O_CLOEXEC) != 0) {
        return std::unexpected("could not create checksum handoff pipe");
    }
    const pid_t child = ::fork();
    if (child < 0) {
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        return std::unexpected("could not start unprivileged request");
    }
    if (child == 0) {
        ::close(pipe_fds[0]);
        if (::dup2(pipe_fds[1], STDOUT_FILENO) < 0) {
            _exit(126);
        }
        ::close(pipe_fds[1]);
        if (::setgroups(groups.size(), groups.data()) != 0 ||
            ::setresgid(gid, gid, gid) != 0 ||
            ::setresuid(uid, uid, uid) != 0) {
            _exit(126);
        }
        ::execve(curl->c_str(), arguments.data(), environment_pointers.data());
        _exit(127);
    }
    ::close(pipe_fds[1]);
    std::string output;
    std::array<char, 4096> buffer{};
    const std::size_t hard_limit = max_bytes + 4096U;
    bool oversized = false;
    for (;;) {
        const auto count = ::read(pipe_fds[0], buffer.data(), buffer.size());
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            oversized = true;
            break;
        }
        if (static_cast<std::size_t>(count) >
            hard_limit - std::min(hard_limit, output.size())) {
            oversized = true;
            break;
        }
        output.append(buffer.data(), static_cast<std::size_t>(count));
    }
    ::close(pipe_fds[0]);
    if (oversized) {
        static_cast<void>(::kill(child, SIGKILL));
    }
    int status = 0;
    pid_t waited = -1;
    do {
        waited = ::waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (oversized || waited != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        return std::unexpected(oversized ? "response exceeds the permitted size"
                                         : "unprivileged HTTPS request failed");
    }
    auto parsed = parse_curl_write_out(output, true);
    if (!parsed) {
        return std::unexpected("response HTTP status is invalid");
    }
    redirect_url = std::move(parsed->redirect_url);
    return HttpResponse{.status = parsed->status,
                        .body = std::move(parsed->body)};
}

std::expected<HttpResponse, std::string> curl_as_user(std::string url,
                                                      std::size_t max_bytes,
                                                      bool api_request,
                                                      uid_t uid) {
    return https_with_redirects(
        std::move(url),
        api_request,
        [&](const std::string& current_url,
            std::string& next_url,
            bool& is_redirect) -> std::expected<HttpResponse, std::string> {
            auto response = curl_get_as_user_once(
                current_url, max_bytes, api_request, uid, next_url);
            if (response && response->status >= 300 && response->status < 400) {
                is_redirect = true;
            }
            return response;
        });
}

std::expected<std::string, std::string>
curl_checksum_as_user(std::string_view url, uid_t uid) {
    auto response = curl_as_user(std::string{url}, 4096, false, uid);
    if (!response) {
        return std::unexpected(response.error());
    }
    if (response->status != 200) {
        return std::unexpected("GitHub checksum request failed with HTTP " +
                               std::to_string(response->status));
    }
    return std::move(response->body);
}
#endif

std::string language_code() {
    return i18n::current_language() == i18n::Language::Portuguese ? "pt-BR"
                                                                  : "en";
}

void select_helper_language(std::string_view language) {
    i18n::set_language(language == "pt-BR" ? i18n::Language::Portuguese
                                           : i18n::Language::English);
}

int report_failure(std::string_view detail) {
    if (platform::cancellation::requested()) {
        return present_cancellation(application::Operation::Preview);
    }
    std::println("{}", i18n::format(i18n::Key::UpdateFailed, detail));
    return 1;
}

} // namespace

std::expected<std::string, std::string>
verify_package_checksum(const std::filesystem::path& archive,
                        const std::filesystem::path& checksum_file,
                        std::string_view archive_name) {
    auto body = read_limited_file(checksum_file, 4096);
    if (!body) {
        return std::unexpected("official SHA-256 checksum could not be read");
    }
    auto expected = parse_checksum(*body, archive_name);
    if (!expected) {
        return std::unexpected(
            "official SHA-256 checksum has an invalid format");
    }
    const auto actual = sha256_file(archive);
    if (!actual) {
        return std::unexpected(actual.error());
    }
    if (lower_ascii(*actual) != *expected) {
        return std::unexpected(
            "downloaded package SHA-256 does not match GitHub");
    }
    return std::move(*expected);
}

namespace {

#if !defined(_WIN32)
std::expected<void, std::string>
install_with_elevation(const std::filesystem::path& executable,
                       const std::filesystem::path& archive,
                       std::string_view tag,
                       std::string_view language) {
#if defined(__linux__)
    const auto pkexec = resolve_linux_system_tool("pkexec");
    const auto sudo = resolve_linux_system_tool("sudo");
    const auto self = platform::path::to_utf8(executable);
    if (!pkexec && !sudo) {
        return std::unexpected(i18n::format(
            i18n::Key::UpdateElevationUnavailable,
            "trusted pkexec and sudo executables are unavailable"));
    }
    const bool interactive = ::isatty(STDIN_FILENO) != 0;
    if (!pkexec && !interactive) {
        return std::unexpected(
            i18n::format(i18n::Key::UpdateElevationUnavailable,
                         "interactive sudo is unavailable"));
    }
    std::println("{}", i18n::tr(i18n::Key::UpdateAdminRequired));
    std::println("{}", i18n::tr(i18n::Key::UpdateRequestPermission));
    const auto result = attempt_linux_elevation(
        interactive,
        pkexec ? LinuxElevationAttempt{[&] {
            const auto environment = linux_pkexec_environment();
            const auto result_proc =
                run_capture({"pkexec",
                             self,
                             "--kasumi-update-install",
                             platform::path::to_utf8(archive),
                             std::string{tag},
                             std::string{language}},
                            PROCESS_OUTPUT_LIMIT,
                            8192,
                            true,
                            &environment);
            if (!result_proc) {
                return LinuxElevationResult{LinuxElevationState::Failed,
                                            "could not run pkexec: " +
                                                result_proc.error()};
            }
            return classify_linux_pkexec_result(result_proc->exit_code,
                                                result_proc->error_output);
        }}
               : LinuxElevationAttempt{},
        sudo ? LinuxElevationAttempt{[&] {
            const auto elevated =
                run_inherited({platform::path::to_utf8(*sudo),
                               "--",
                               self,
                               "--kasumi-update-install",
                               platform::path::to_utf8(archive),
                               std::string{tag},
                               std::string{language}});
            return elevated
                       ? LinuxElevationResult{LinuxElevationState::Succeeded,
                                              {}}
                       : LinuxElevationResult{LinuxElevationState::Failed,
                                              elevated.error()};
        }}
             : LinuxElevationAttempt{});
    if (result.state != LinuxElevationState::Succeeded) {
        if (result.detail.empty()) {
            return std::unexpected(
                i18n::format(i18n::Key::UpdateElevationUnavailable,
                             "pkexec or sudo could not authorize the update"));
        }
        return std::unexpected(result.detail);
    }
    return {};
#else
    static_cast<void>(executable);
    static_cast<void>(archive);
    static_cast<void>(tag);
    static_cast<void>(language);
    return std::unexpected(
        i18n::format(i18n::Key::UpdateElevationUnavailable,
                     "elevation is unsupported on this platform"));
#endif
}
#endif

#if defined(_WIN32)

std::wstring quote_windows_argument(std::wstring_view value) {
    std::wstring result{L"\""};
    std::size_t slashes = 0;
    for (const wchar_t character : value) {
        if (character == L'\\') {
            ++slashes;
            continue;
        }
        if (character == L'"') {
            result.append(slashes * 2 + 1, L'\\');
            result.push_back(character);
            slashes = 0;
            continue;
        }
        result.append(slashes, L'\\');
        slashes = 0;
        result.push_back(character);
    }
    result.append(slashes * 2, L'\\');
    result.push_back(L'"');
    return result;
}

std::wstring
join_windows_arguments(const std::vector<std::wstring>& arguments) {
    std::wstring result;
    for (const auto& argument : arguments) {
        if (!result.empty()) {
            result.push_back(L' ');
        }
        result += quote_windows_argument(argument);
    }
    return result;
}

std::optional<std::filesystem::path> windows_process_path(DWORD process_id,
                                                          HANDLE& handle) {
    handle = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, process_id);
    if (handle == nullptr) {
        return std::nullopt;
    }
    std::vector<wchar_t> buffer(32768);
    DWORD length = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(handle, 0, buffer.data(), &length)) {
        CloseHandle(handle);
        handle = nullptr;
        return std::nullopt;
    }
    std::error_code error;
    auto path = std::filesystem::canonical(
        std::filesystem::path{std::wstring_view{buffer.data(), length}}, error);
    if (error) {
        CloseHandle(handle);
        handle = nullptr;
        return std::nullopt;
    }
    return path;
}

std::optional<DWORD> windows_parent_process_id(DWORD process_id) {
    const ScopedWindowsHandle snapshot{
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if (!snapshot) {
        return std::nullopt;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::optional<DWORD> result;
    if (Process32FirstW(snapshot.value, &entry)) {
        do {
            if (entry.th32ProcessID == process_id) {
                result = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot.value, &entry));
    }
    return result;
}

bool windows_path_has_no_reparse_points(const std::filesystem::path& path) {
    if (!path.is_absolute()) {
        return false;
    }
    auto current = path.root_path();
    if (current.empty() || !windows_entry_is_not_reparse_point(current)) {
        return false;
    }
    for (const auto& component : path.relative_path()) {
        if (component.empty() || component == L".") {
            continue;
        }
        if (component == L".." ||
            !windows_entry_is_not_reparse_point(current /= component)) {
            return false;
        }
    }
    return true;
}

std::string windows_identity_text(const WindowsFileIdentity& identity) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result(16, '0');
    auto serial = identity.volume_serial;
    for (std::size_t index = 0; index < 16; ++index) {
        result[15 - index] = hex[serial & 0x0fU];
        serial >>= 4U;
    }
    return result + bytes_to_hex(identity.file_id);
}

std::optional<WindowsFileIdentity>
parse_windows_identity(std::string_view value) {
    if (value.size() != 48 || !is_hex_string(value)) {
        return std::nullopt;
    }
    WindowsFileIdentity result;
    const auto [serial_end, serial_error] = std::from_chars(
        value.data(), value.data() + 16, result.volume_serial, 16);
    if (serial_error != std::errc{} || serial_end != value.data() + 16) {
        return std::nullopt;
    }
    const auto nibble = [](char character) -> std::uint8_t {
        if (character >= '0' && character <= '9') {
            return static_cast<std::uint8_t>(character - '0');
        }
        if (character >= 'a' && character <= 'f') {
            return static_cast<std::uint8_t>(character - 'a' + 10);
        }
        return static_cast<std::uint8_t>(character - 'A' + 10);
    };
    for (std::size_t index = 0; index < result.file_id.size(); ++index) {
        result.file_id[index] =
            static_cast<std::uint8_t>((nibble(value[16 + index * 2]) << 4U) |
                                      nibble(value[17 + index * 2]));
    }
    return result;
}

bool is_kasumi_executable(const std::filesystem::path& path) {
    DWORD ignored = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (size == 0 || size > 1024U * 1024U) {
        return false;
    }
    std::vector<std::byte> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data())) {
        return false;
    }
    VS_FIXEDFILEINFO* fixed = nullptr;
    UINT fixed_size = 0;
    if (!VerQueryValueW(data.data(),
                        L"\\",
                        reinterpret_cast<void**>(&fixed),
                        &fixed_size) ||
        fixed == nullptr || fixed_size < sizeof(VS_FIXEDFILEINFO) ||
        fixed->dwFileType != VFT_APP) {
        return false;
    }
    const auto matches = [&](std::wstring_view key,
                             std::wstring_view expected) {
        const std::wstring query =
            L"\\StringFileInfo\\040904b0\\" + std::wstring{key};
        void* value = nullptr;
        UINT length = 0;
        return VerQueryValueW(data.data(), query.c_str(), &value, &length) &&
               value != nullptr && length > 0 &&
               std::wstring_view{static_cast<const wchar_t*>(value),
                                 length - 1} == expected;
    };
    return matches(L"ProductName", L"Kasumi") &&
           matches(L"OriginalFilename", L"kasumi.exe");
}

std::expected<void, std::string>
start_windows_helper(const std::filesystem::path& executable,
                     const std::filesystem::path& archive,
                     std::string_view version,
                     const WindowsFileIdentity& target_identity,
                     const platform::Workspace& workspace) {
    auto id = platform::random::hex_id();
    if (!id) {
        return std::unexpected(id.error());
    }
    std::error_code error;
    const auto helper =
        workspace.root /
        platform::path::from_utf8("kasumi-update-helper-" + *id + ".exe");
    if (!std::filesystem::copy_file(
            executable, helper, std::filesystem::copy_options::none, error) ||
        error) {
        return std::unexpected(
            "could not prepare the Windows replacement helper");
    }
    const auto self_process = GetCurrentProcessId();
    const auto version_w = widen_ascii(version);
    const auto language_w = widen_ascii(language_code());
    const auto identity_w = widen_ascii(windows_identity_text(target_identity));
    if (!version_w || !language_w || !identity_w || !workspace.identity.valid ||
        !windows_path_has_no_reparse_points(executable) ||
        !windows_file_identity_matches(executable, target_identity)) {
        std::filesystem::remove(helper, error);
        return std::unexpected("invalid installer handoff arguments");
    }
    const auto command_line = join_windows_arguments(
        {helper.wstring(),
         L"--kasumi-update-helper",
         archive.wstring(),
         *version_w,
         *language_w,
         std::to_wstring(self_process),
         *identity_w,
         std::to_wstring(workspace.identity.volume_or_dev),
         std::to_wstring(workspace.identity.file_id_low),
         std::to_wstring(workspace.identity.file_id_high)});
    std::vector<wchar_t> mutable_command(command_line.begin(),
                                         command_line.end());
    mutable_command.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(helper.c_str(),
                        mutable_command.data(),
                        nullptr,
                        nullptr,
                        TRUE,
                        CREATE_UNICODE_ENVIRONMENT,
                        nullptr,
                        nullptr,
                        &startup,
                        &process)) {
        std::filesystem::remove(helper, error);
        return std::unexpected(
            "could not start the Windows replacement helper");
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    const auto ready_path = workspace.root / "helper-ready";
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{10};
    while (std::chrono::steady_clock::now() < deadline) {
        if (std::filesystem::exists(ready_path, error) && !error) {
            return {};
        }
        Sleep(20);
    }
    std::filesystem::remove(helper, error);
    return std::unexpected("Windows replacement helper did not initialize");
}

int run_windows_wait_helper(int argc, char* argv[]) {
    if (argc != 10 || argv[2] == nullptr || argv[3] == nullptr ||
        argv[4] == nullptr || argv[5] == nullptr || argv[6] == nullptr ||
        argv[7] == nullptr || argv[8] == nullptr || argv[9] == nullptr) {
        return report_failure("invalid installer handoff");
    }
    select_helper_language(argv[4]);
    const auto archive = platform::path::from_utf8(argv[2]);
    const std::string_view version{argv[3]};
    const auto helper = current_executable_path();
    const auto package = package_names_for_this_platform();
    if (!helper || !package) {
        return report_failure(
            "could not identify the Windows installer helper");
    }
    DWORD parent_id = 0;
    const auto [end, parse_error] = std::from_chars(
        argv[5], argv[5] + std::char_traits<char>::length(argv[5]), parent_id);
    if (parse_error != std::errc{} || *end != '\0') {
        return report_failure("invalid installer parent process");
    }
    const auto expected_identity = parse_windows_identity(argv[6]);
    const auto parse_workspace_identity =
        [](const char* text) -> std::optional<std::uint64_t> {
        std::uint64_t value = 0;
        const auto finish = text + std::char_traits<char>::length(text);
        const auto [position, error] = std::from_chars(text, finish, value);
        if (error != std::errc{} || position != finish) {
            return std::nullopt;
        }
        return value;
    };
    const auto workspace_volume = parse_workspace_identity(argv[7]);
    const auto workspace_id_low = parse_workspace_identity(argv[8]);
    const auto workspace_id_high = parse_workspace_identity(argv[9]);
    if (!expected_identity || !workspace_volume || !workspace_id_low ||
        !workspace_id_high ||
        windows_parent_process_id(GetCurrentProcessId()) != parent_id) {
        return report_failure(
            "installer was not started by the original Kasumi process");
    }
    HANDLE parent = nullptr;
    const auto parent_path = windows_process_path(parent_id, parent);
    ScopedWindowsHandle keep_parent{parent};
    if (!parent_path || !is_kasumi_executable(*parent_path) ||
        !windows_path_has_no_reparse_points(*parent_path) ||
        parent_path->filename() != "kasumi.exe" ||
        !windows_file_identity_matches(*parent_path, *expected_identity)) {
        if (parent != nullptr) {
            keep_parent.value = nullptr;
            CloseHandle(parent);
        }
        return report_failure("installer parent is not a Kasumi executable");
    }
    const auto target = *parent_path;
    std::error_code error;
    const auto root = archive.parent_path();
    auto valid_root = validate_staging_root(root);
    if (!valid_root ||
        archive.filename() != platform::path::from_utf8(package->archive) ||
        !is_regular_file_without_redirect(archive) ||
        !windows_entry_is_not_reparse_point(root) ||
        !windows_file_identity(archive)) {
        return report_failure("update staging directory is invalid");
    }
    const auto ready = root / "helper-ready";
    const platform::Workspace handoff_workspace{
        .root = root,
        .identity = {.volume_or_dev = *workspace_volume,
                     .file_id_low = *workspace_id_low,
                     .file_id_high = *workspace_id_high,
                     .valid = true}};
    if (platform::private_storage::query_directory_identity(root) !=
        handoff_workspace.identity) {
        return report_failure("update staging workspace identity changed");
    }
    {
        std::ofstream marker(ready, std::ios::binary | std::ios::trunc);
        if (!marker) {
            return report_failure("could not initialize installer handoff");
        }
        marker << "ready";
    }
    struct HandoffCleanup {
        platform::Workspace workspace;
        std::filesystem::path helper;
        ~HandoffCleanup() {
            platform::cleanup_workspace(workspace);
            static_cast<void>(MoveFileExW(
                helper.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT));
        }
    } cleanup{.workspace = handoff_workspace, .helper = *helper};
    const DWORD parent_wait = WaitForSingleObject(parent, INFINITE);
    if (parent_wait != WAIT_OBJECT_0) {
        return report_failure("could not wait for the running Kasumi process");
    }
    std::string manager;
    if (package_managed_installation(target, manager)) {
        return report_failure(
            i18n::format(i18n::Key::UpdateManagedInstallation, manager));
    }
    auto digest =
        refetch_official_digest(archive, version, *package, handoff_workspace);
    if (!digest) {
        return report_failure(digest.error());
    }
    const auto prepared = prepare_archive_for_install(
        archive, *digest, *package, "helper-verify");
    if (!prepared) {
        return report_failure(prepared.error());
    }
    if (!windows_path_has_no_reparse_points(target) ||
        !windows_file_identity_matches(target, *expected_identity)) {
        return report_failure(
            "installation destination changed before replacement");
    }
    InstallHooks target_identity_hook;
    target_identity_hook.validate_target =
        [expected = *expected_identity](const std::filesystem::path& candidate)
        -> std::expected<void, std::string> {
        if (!windows_path_has_no_reparse_points(candidate) ||
            !windows_file_identity_matches(candidate, expected)) {
            return std::unexpected(
                "installation destination changed before replacement");
        }
        return {};
    };
    auto installed = install_prepared_executable(
        prepared->path, target, prepared->sha256, &target_identity_hook);
    platform::cleanup_workspace(prepared->workspace);
    if (!installed) {
        if (installed.error().kind == InstallFailure::Kind::PermissionDenied) {
            return report_failure(i18n::tr(i18n::Key::UpdateAdminRequired));
        }
        return report_failure(installed.error().detail);
    }
    const auto installed_version = parse_version(version);
    if (!installed_version) {
        return report_failure("installed release version is invalid");
    }
    std::println(
        "{}",
        i18n::format(i18n::Key::UpdateCompleted, installed_version->text));
    return 0;
}

#endif

int run_public_update(bool allow_elevation);

} // namespace

#if defined(__linux__)
std::expected<std::filesystem::path, std::string>
resolve_linux_system_tool(std::string_view name) {
    const bool allowed = std::ranges::find(LINUX_SYSTEM_TOOLS, name) !=
                             LINUX_SYSTEM_TOOLS.end() ||
                         std::ranges::find(LINUX_ELEVATION_TOOLS, name) !=
                             LINUX_ELEVATION_TOOLS.end();
    if (!allowed) {
        return std::unexpected(
            "tool is not on the updater system-tool allowlist");
    }
    for (const auto& directory : linux_tool_directories()) {
        const auto candidate = directory / platform::path::from_utf8(name);
        std::error_code error;
        const auto status = std::filesystem::symlink_status(candidate, error);
        if (error == std::errc::no_such_file_or_directory ||
            status.type() == std::filesystem::file_type::not_found) {
            continue;
        }
        if (error) {
            return std::unexpected("could not inspect system tool: " +
                                   std::string{name});
        }
        auto valid = validate_linux_system_tool(candidate);
        if (!valid) {
            return std::unexpected("unsafe system tool " + std::string{name} +
                                   ": " + valid.error());
        }
        const auto resolved = std::filesystem::canonical(candidate, error);
        if (error) {
            return std::unexpected("could not resolve trusted system tool: " +
                                   std::string{name});
        }
        return resolved;
    }
    return std::unexpected("trusted system tool not found: " +
                           std::string{name});
}

std::expected<void, std::string>
validate_linux_system_tool(const std::filesystem::path& path) {
    if (auto checked = validate_root_path(path, false, true); !checked) {
        return checked;
    }
    std::error_code error;
    const auto canonical = std::filesystem::canonical(path, error);
    struct stat file_status{};
    if (error || ::stat(canonical.c_str(), &file_status) != 0 ||
        !trusted_root_stat(file_status, false) ||
        (file_status.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0 ||
        !trusted_canonical_path(canonical, false)) {
        return std::unexpected(
            "system tool or one of its directories is not root-controlled");
    }
    return {};
}

LinuxElevationResult
classify_linux_pkexec_result(int exit_code, std::string_view error_output) {
    if (exit_code == 0) {
        return {LinuxElevationState::Succeeded, {}};
    }
    if (exit_code == 126) {
        return {LinuxElevationState::Cancelled, std::string{error_output}};
    }
    for (const auto marker :
         {std::string_view{"Error executing command as another user: No "
                           "authentication agent found."},
          std::string_view{"Error creating textual authentication agent:"},
          std::string_view{"Error registering local authentication agent:"}}) {
        if (error_output.find(marker) != std::string_view::npos) {
            return {LinuxElevationState::AuthenticationUnavailable,
                    std::string{error_output}};
        }
    }
    return {LinuxElevationState::Failed,
            error_output.empty() ? "pkexec failed" : std::string{error_output}};
}

LinuxElevationResult
attempt_linux_elevation(bool interactive,
                        const LinuxElevationAttempt& pkexec,
                        const LinuxElevationAttempt& sudo) {
    if (pkexec) {
        const auto result = pkexec();
        if (result.state != LinuxElevationState::AuthenticationUnavailable ||
            !interactive || !sudo) {
            return result;
        }
        return sudo();
    }
    if (interactive && sudo) {
        return sudo();
    }
    return {LinuxElevationState::Failed,
            "pkexec and interactive sudo are unavailable"};
}

InstallResult install_linux_handoff(const std::filesystem::path& archive,
                                    std::string_view tag,
                                    const std::filesystem::path& target,
                                    const LinuxHandoffHooks& hooks) {
    const auto package = package_names_for_this_platform();
    if (!package ||
        archive.filename() != platform::path::from_utf8(package->archive) ||
        !is_regular_file_without_redirect(archive) || !parse_version(tag) ||
        !hooks.fetch_checksum || !hooks.prepare || !hooks.install) {
        return std::unexpected(
            install_failure("invalid privileged update handoff"));
    }
    const std::string checksum_url =
        make_official_asset_url(tag, package->checksum);
    if (!official_asset_url(tag, package->checksum, checksum_url)) {
        return std::unexpected(
            install_failure("official checksum URL is invalid"));
    }
    auto checksum_body = hooks.fetch_checksum(checksum_url);
    if (!checksum_body) {
        return std::unexpected(install_failure(checksum_body.error()));
    }
    const auto expected = parse_checksum(*checksum_body, package->archive);
    if (!expected) {
        return std::unexpected(
            install_failure("official checksum has an invalid format"));
    }
    const auto actual = sha256_file(archive);
    if (!actual || lower_ascii(*actual) != *expected) {
        return std::unexpected(install_failure(
            actual ? "package changed or does not match the official checksum"
                   : actual.error()));
    }
    auto prepared = hooks.prepare(archive, *expected);
    if (!prepared) {
        return std::unexpected(install_failure(prepared.error()));
    }
    if (!valid_sha256(prepared->sha256)) {
        return std::unexpected(
            install_failure("prepared executable digest is invalid"));
    }
    return hooks.install(*prepared, target);
}
#endif

namespace {

#if defined(__linux__)
bool copy_private_staged_archive(const std::filesystem::path& archive,
                                 const std::filesystem::path& trusted_archive,
                                 uid_t expected_uid,
                                 std::size_t max_bytes) {
    const int dir_fd = ::open(archive.parent_path().c_str(),
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir_fd < 0) {
        return false;
    }
    platform::private_storage::PrivateHandle dir_guard{dir_fd};
    struct stat dir_stat{};
    if (::fstat(dir_fd, &dir_stat) != 0 || !S_ISDIR(dir_stat.st_mode) ||
        dir_stat.st_uid != expected_uid || (dir_stat.st_mode & 0077) != 0) {
        return false;
    }
    const int src_fd = ::openat(
        dir_fd, archive.filename().c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (src_fd < 0) {
        return false;
    }
    platform::private_storage::PrivateHandle src_guard{src_fd};
    struct stat src_stat{};
    if (::fstat(src_fd, &src_stat) != 0 || !S_ISREG(src_stat.st_mode) ||
        src_stat.st_uid != expected_uid || src_stat.st_size <= 0 ||
        static_cast<std::uint64_t>(src_stat.st_size) > max_bytes) {
        return false;
    }
    const int dst_fd =
        ::open(trusted_archive.c_str(),
               O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
               0600);
    if (dst_fd < 0) {
        return false;
    }
    platform::private_storage::PrivateHandle dst_guard{dst_fd};
    std::array<char, 65536> buffer{};
    std::size_t copied = 0;
    for (;;) {
        const auto count = ::read(src_fd, buffer.data(), buffer.size());
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        const auto chunk = static_cast<std::size_t>(count);
        if (chunk > max_bytes - copied) {
            return false;
        }
        std::size_t offset = 0;
        while (offset < chunk) {
            const auto written =
                ::write(dst_fd, buffer.data() + offset, chunk - offset);
            if (written < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return false;
            }
            offset += static_cast<std::size_t>(written);
        }
        copied += chunk;
    }
    return copied > 0 && copied == static_cast<std::size_t>(src_stat.st_size);
}

int run_linux_install_helper(int argc, char* argv[]) {
    if (argc != 5 || argv[2] == nullptr || argv[3] == nullptr ||
        argv[4] == nullptr ||
        (std::string_view{argv[4]} != "en" &&
         std::string_view{argv[4]} != "pt-BR")) {
        return report_failure("invalid installer handoff");
    }
    select_helper_language(argv[4]);
    if (::geteuid() != 0) {
        return report_failure("privileged installer must run as root");
    }
    const auto uid = invoking_user_id();
    const auto package = package_names_for_this_platform();
    const auto target = current_executable_path();
    const auto target_id =
        target ? platform::private_storage::query_file_identity(*target)
               : platform::private_storage::FileIdentity{};
    if (!uid || !package || !target || !target_id.valid ||
        target->filename() != "kasumi") {
        return report_failure(
            "could not validate the privileged update handoff");
    }
    const auto archive = platform::path::from_utf8(argv[2]);
    const std::string_view tag{argv[3]};
    const auto current = parse_version(KASUMI_VERSION);
    const auto requested = parse_version(tag);
    if (!current || !requested || compare_versions(*requested, *current) <= 0) {
        return report_failure("installer handoff release is invalid or older");
    }
    auto stage_valid = validate_staging_root(archive.parent_path());
    if (!stage_valid ||
        archive.filename() != platform::path::from_utf8(package->archive) ||
        !is_regular_file_without_redirect(archive)) {
        return report_failure(
            "update package is outside the original private staging directory");
    }
    std::string manager;
    if (package_managed_installation(*target, manager)) {
        return report_failure(
            i18n::format(i18n::Key::UpdateManagedInstallation, manager));
    }
    auto releases = fetch_releases(
        [uid = *uid](std::string_view url, std::size_t max_bytes) {
            return curl_as_user(std::string{url}, max_bytes, true, uid);
        });
    if (!releases) {
        return report_failure(releases.error());
    }
    const auto selected = select_release_index(*releases);
    if (!selected || (*releases)[*selected].tag != tag) {
        return report_failure("official update release changed during handoff");
    }
    auto workspace = platform::create_workspace("update-elevated");
    if (!workspace) {
        return report_failure(workspace.error());
    }
    const ScopedWorkspaceCleanup cleanup{.value = *workspace};
    const auto trusted_archive =
        platform::workspace_file(*workspace, package->archive);
    if (trusted_archive.empty() ||
        !copy_private_staged_archive(
            archive, trusted_archive, *uid, PACKAGE_LIMIT)) {
        return report_failure(
            "could not copy update package into a private workspace");
    }
    LinuxHandoffHooks hooks;
    hooks.fetch_checksum = [uid = *uid](std::string_view url) {
        return curl_checksum_as_user(url, uid);
    };
    hooks.prepare = [&](const std::filesystem::path& source,
                        std::string_view digest)
        -> std::expected<PreparedExecutable, std::string> {
        return prepare_verified_package(source, digest, *package, *workspace);
    };
    hooks.install = [target_id](const PreparedExecutable& prepared,
                                const std::filesystem::path& destination) {
        InstallHooks install_hooks;
        install_hooks.validate_target =
            [target_id](const std::filesystem::path& dest)
            -> std::expected<void, std::string> {
            const auto current_id =
                platform::private_storage::query_file_identity(dest);
            if (!current_id.valid || !(current_id == target_id)) {
                return std::unexpected(
                    "installed kasumi binary changed during update");
            }
            return {};
        };
        return install_prepared_executable(
            prepared.path, destination, prepared.sha256, &install_hooks);
    };
    const auto installed =
        install_linux_handoff(trusted_archive, tag, *target, hooks);
    if (!installed) {
        return report_failure(installed.error().detail);
    }
    return 0;
}
#endif

int run_public_update(bool allow_elevation = true) {
    if (platform::cancellation::requested()) {
        return present_cancellation(application::Operation::Preview);
    }
#if defined(_WIN32)
    (void)allow_elevation;
#endif
    std::println("{}", i18n::tr(i18n::Key::UpdateChecking));
    const auto package = package_names_for_this_platform();
    if (!package) {
        return report_failure(
            "this operating system or architecture is unsupported");
    }
    const auto executable = current_executable_path();
    if (!executable) {
        return report_failure(
            "could not identify the running executable safely");
    }
#if defined(_WIN32)
    if (executable->filename() != "kasumi.exe") {
        return report_failure("installation destination is not kasumi.exe");
    }
    if (!windows_path_has_no_reparse_points(*executable)) {
        return report_failure("installation path contains a reparse point");
    }
    const auto target_identity = windows_file_identity(*executable);
    if (!target_identity) {
        return report_failure(
            "could not identify the running installation file");
    }
    const auto writable = check_windows_installation_writable(*executable);
    if (writable.state == WindowsInstallationWritableState::PermissionDenied) {
        return report_failure(i18n::tr(i18n::Key::UpdateAdminRequired));
    }
    if (writable.state != WindowsInstallationWritableState::Writable) {
        return report_failure(writable.detail);
    }
#else
    if (executable->filename() != "kasumi") {
        return report_failure("installation destination is not kasumi");
    }
#endif
    std::string manager;
    if (package_managed_installation(*executable, manager)) {
        return report_failure(
            i18n::format(i18n::Key::UpdateManagedInstallation, manager));
    }
    const auto current = parse_version(KASUMI_VERSION);
    if (!current) {
        return report_failure("installed version metadata is invalid");
    }
    std::println("{}",
                 i18n::format(i18n::Key::UpdateCurrentVersion, current->text));
    auto workspace = platform::create_workspace("update");
    if (!workspace) {
        return report_failure(workspace.error());
    }
#if defined(_WIN32)
    auto admin_read = grant_windows_admin_read_access(workspace->root);
    if (!admin_read) {
        platform::cleanup_workspace(*workspace);
        return report_failure(admin_read.error());
    }
#endif
    ScopedWorkspaceCleanup cleanup{.value = *workspace};
    auto releases = fetch_releases(make_workspace_api_get(*workspace));
    if (!releases) {
        return report_failure(releases.error());
    }
    if (platform::cancellation::requested()) {
        return present_cancellation(application::Operation::Preview);
    }
    const auto selected = select_release_index(*releases);
    if (!selected) {
        return report_failure(
            "no release is available for this update channel");
    }
    const auto version = parse_version((*releases)[*selected].tag);
    if (!version) {
        return report_failure("selected release version is invalid");
    }
    std::println("{}",
                 i18n::format(i18n::Key::UpdateLatestVersion, version->text));
    if (installed_version_is_current_or_newer(current->text, *version)) {
        std::println("{}", i18n::tr(i18n::Key::UpdateAlreadyCurrent));
        return 0;
    }
    const auto archive_url =
        release_asset_url((*releases)[*selected], package->archive);
    const auto checksum_url =
        release_asset_url((*releases)[*selected], package->checksum);
    if (!archive_url || !checksum_url) {
        return report_failure(
            "selected release is missing official package assets");
    }
    const auto archive = platform::workspace_file(*workspace, package->archive);
    const auto checksum_file =
        platform::workspace_file(*workspace, "package.sha256");
    if (archive.empty() || checksum_file.empty()) {
        return report_failure("could not allocate download paths");
    }
    std::println("{}", i18n::tr(i18n::Key::UpdateDownloading));
    auto downloaded =
        download_asset(*archive_url, archive, PACKAGE_LIMIT, *workspace);
    if (!downloaded) {
        return report_failure(downloaded.error());
    }
    downloaded = download_asset(*checksum_url, checksum_file, 4096, *workspace);
    if (!downloaded) {
        return report_failure(downloaded.error());
    }
    std::println("{}", i18n::tr(i18n::Key::UpdateVerifying));
    auto verified =
        verify_package_checksum(archive, checksum_file, package->archive);
    if (!verified) {
        return report_failure(verified.error());
    }
    const std::string digest = std::move(*verified);
    const auto prepared =
        prepare_verified_package(archive, digest, *package, *workspace);
    if (!prepared) {
        return report_failure(prepared.error());
    }
    if (platform::cancellation::requested()) {
        return present_cancellation(application::Operation::Preview);
    }
    std::println("{}", i18n::tr(i18n::Key::UpdateInstalling));
#if defined(_WIN32)
    auto launched = start_windows_helper(*executable,
                                         archive,
                                         (*releases)[*selected].tag,
                                         *target_identity,
                                         *workspace);
    if (!launched) {
        return report_failure(launched.error());
    }
    cleanup.released = true;
    std::println("{}", i18n::tr(i18n::Key::UpdateHandoffStarted));
    return 0;
#else
    const InstallAction direct = [&]() -> InstallResult {
        return install_prepared_executable(
            prepared->path, *executable, prepared->sha256);
    };
    const InstallAction elevate = [&]() -> InstallResult {
        if (!allow_elevation) {
            return std::unexpected(InstallFailure{
                .kind = InstallFailure::Kind::Other,
                .detail =
                    "privileged installer could not replace the executable"});
        }
        auto elevated = install_with_elevation(
            *executable, archive, (*releases)[*selected].tag, language_code());
        if (!elevated) {
            return std::unexpected(
                InstallFailure{.kind = InstallFailure::Kind::Other,
                               .detail = elevated.error()});
        }
        return {};
    };
    const auto installed = install_once_then_elevate(direct, elevate);
    if (!installed) {
        return report_failure(installed.error().detail);
    }
    std::println("{}", i18n::format(i18n::Key::UpdateCompleted, version->text));
    return 0;
#endif
}

} // namespace

#if defined(_WIN32)
WindowsInstallationWritableResult check_windows_installation_writable(
    const std::filesystem::path& target,
    const WindowsIdentifierGenerator& id_generator) {
    auto id = id_generator ? id_generator() : platform::random::hex_id();
    if (!id) {
        return WindowsInstallationWritableResult{
            .state = WindowsInstallationWritableState::OtherFailure,
            .detail = "could not generate probe identifier: " + id.error()};
    }
    const auto probe = target.parent_path() /
                       platform::path::from_utf8(".kasumi-probe-" + *id);
    HANDLE handle =
        CreateFileW(probe.c_str(),
                    GENERIC_WRITE | DELETE,
                    0,
                    nullptr,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD) {
            return WindowsInstallationWritableResult{
                .state = WindowsInstallationWritableState::PermissionDenied,
                .detail = "access denied to installation directory"};
        }
        return WindowsInstallationWritableResult{
            .state = WindowsInstallationWritableState::OtherFailure,
            .detail = "probe creation failed: " +
                      std::system_category().message(static_cast<int>(error))};
    }
    CloseHandle(handle);
    return WindowsInstallationWritableResult{
        .state = WindowsInstallationWritableState::Writable, .detail = {}};
}

std::expected<void, std::string>
grant_windows_admin_read_access(const std::filesystem::path& root) {
    auto acl = query_windows_workspace_acl(
        root, "could not inspect update workspace permissions");
    if (!acl) {
        return std::unexpected(acl.error());
    }
    WindowsWellKnownSid system_sid;
    WindowsWellKnownSid admin_sid;
    std::vector<std::byte> token_data;
    bool valid = acl->protected_dacl && acl->owner != nullptr &&
                 system_sid.init(WinLocalSystemSid) &&
                 admin_sid.init(WinBuiltinAdministratorsSid) &&
                 query_current_user_token(token_data) &&
                 acl->info.AceCount == 2;
    const auto* current_user =
        valid ? reinterpret_cast<const TOKEN_USER*>(token_data.data())
              : nullptr;
    bool has_workspace_user = false;
    bool has_system = false;
    PSID workspace_user = nullptr;
    for (DWORD index = 0; valid && index < acl->info.AceCount; ++index) {
        void* raw = nullptr;
        if (!GetAce(acl->dacl, index, &raw) || raw == nullptr) {
            valid = false;
            break;
        }
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        auto* sid = reinterpret_cast<PSID>(&ace->SidStart);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            ace->Mask != FILE_ALL_ACCESS) {
            valid = false;
        } else if (EqualSid(sid, system_sid.get())) {
            has_system = true;
        } else if (current_user != nullptr &&
                   EqualSid(sid, current_user->User.Sid)) {
            has_workspace_user = true;
            workspace_user = sid;
        } else {
            valid = false;
        }
    }
    const bool owner_is_expected =
        acl->owner != nullptr &&
        ((workspace_user != nullptr && EqualSid(acl->owner, workspace_user)) ||
         EqualSid(acl->owner, admin_sid.get()));
    if (!valid || !has_workspace_user || !has_system || !owner_is_expected) {
        return std::unexpected(
            "update workspace ACL is not the expected private ACL");
    }
    EXPLICIT_ACCESSW access{};
    access.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(admin_sid.get());
    PACL updated_acl = nullptr;
    const auto merge = SetEntriesInAclW(1, &access, acl->dacl, &updated_acl);
    const LocalSecurityDescriptor updated_guard{updated_acl};
    acl->descriptor.reset();
    if (merge != ERROR_SUCCESS || !updated_guard) {
        return std::unexpected("could not grant read-only administrator access "
                               "to update workspace");
    }
    std::wstring writable = root.wstring();
    const auto set = SetNamedSecurityInfoW(
        writable.data(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        updated_acl,
        nullptr);
    if (set != ERROR_SUCCESS) {
        return std::unexpected(
            "could not secure update workspace for UAC handoff");
    }
    return validate_windows_workspace_acl(root);
}

std::expected<void, std::string>
validate_windows_workspace_acl(const std::filesystem::path& root) {
    auto acl = query_windows_workspace_acl(
        root, "could not verify update workspace permissions");
    if (!acl) {
        return std::unexpected(acl.error());
    }
    WindowsWellKnownSid system_sid;
    WindowsWellKnownSid admin_sid;
    bool valid = acl->protected_dacl && acl->owner != nullptr &&
                 system_sid.init(WinLocalSystemSid) &&
                 admin_sid.init(WinBuiltinAdministratorsSid) &&
                 acl->info.AceCount == 3;
    bool has_workspace_user = false;
    bool has_system = false;
    bool has_admin_read = false;
    PSID workspace_user = nullptr;
    for (DWORD index = 0; valid && index < acl->info.AceCount; ++index) {
        void* raw_ace = nullptr;
        if (!GetAce(acl->dacl, index, &raw_ace) || raw_ace == nullptr) {
            valid = false;
            break;
        }
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) {
            valid = false;
            break;
        }
        auto* sid = reinterpret_cast<PSID>(&ace->SidStart);
        constexpr BYTE expected_flags =
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        if (ace->Header.AceFlags != expected_flags) {
            valid = false;
            break;
        }
        if (EqualSid(sid, system_sid.get())) {
            has_system = ace->Mask == FILE_ALL_ACCESS;
        } else if (EqualSid(sid, admin_sid.get())) {
            has_admin_read =
                ace->Mask == (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE);
        } else if (ace->Mask == FILE_ALL_ACCESS && !has_workspace_user &&
                   !IsWellKnownSid(sid, WinWorldSid) &&
                   !IsWellKnownSid(sid, WinBuiltinUsersSid) &&
                   !IsWellKnownSid(sid, WinAuthenticatedUserSid) &&
                   !IsWellKnownSid(sid, WinBuiltinGuestsSid) &&
                   !IsWellKnownSid(sid, WinAnonymousSid)) {
            has_workspace_user = true;
            workspace_user = sid;
        } else {
            valid = false;
        }
    }
    std::vector<std::byte> token_data;
    valid = valid && query_current_user_token(token_data);
    const auto* current_user =
        valid ? reinterpret_cast<const TOKEN_USER*>(token_data.data())
              : nullptr;
    const bool current_is_owner =
        current_user != nullptr && workspace_user != nullptr &&
        EqualSid(current_user->User.Sid, workspace_user);
    BOOL is_member = FALSE;
    const bool current_is_admin =
        valid && !current_is_owner &&
        CheckTokenMembership(nullptr, admin_sid.get(), &is_member) != 0 &&
        is_member;
    const bool owner_is_expected = acl->owner != nullptr &&
                                   workspace_user != nullptr &&
                                   (EqualSid(acl->owner, workspace_user) ||
                                    EqualSid(acl->owner, admin_sid.get()));
    if (!valid || !owner_is_expected || !has_workspace_user || !has_system ||
        !has_admin_read || (!current_is_owner && !current_is_admin)) {
        return std::unexpected("update workspace ACL does not preserve owner "
                               "privacy and administrator read access");
    }
    return {};
}

std::optional<WindowsFileIdentity>
windows_file_identity(const std::filesystem::path& path) {
    FILE_ID_INFO info{};
    if (!windows_has_attribute_flags(path,
                                     0,
                                     FILE_ATTRIBUTE_REPARSE_POINT |
                                         FILE_ATTRIBUTE_DIRECTORY,
                                     &info)) {
        return std::nullopt;
    }
    WindowsFileIdentity result;
    result.volume_serial = info.VolumeSerialNumber;
    std::memcpy(
        result.file_id.data(), info.FileId.Identifier, result.file_id.size());
    return result;
}

bool windows_file_identity_matches(const std::filesystem::path& path,
                                   const WindowsFileIdentity& expected) {
    const auto actual = windows_file_identity(path);
    return actual && *actual == expected;
}

std::wstring
windows_join_arguments(const std::vector<std::wstring>& arguments) {
    return join_windows_arguments(arguments);
}

std::optional<std::vector<std::wstring>>
windows_decode_arguments(std::wstring_view command_line) {
    if (command_line.find(L'\0') != std::wstring_view::npos) {
        return std::nullopt;
    }
    const std::wstring terminated{command_line};
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(terminated.c_str(), &argc);
    if (argv == nullptr || argc <= 0) {
        return std::nullopt;
    }
    std::vector<std::wstring> result;
    result.reserve(static_cast<std::size_t>(argc));
    for (int index = 0; index < argc; ++index) {
        result.emplace_back(argv[index]);
    }
    LocalFree(argv);
    return result;
}
#endif

int run(int argc, char* argv[]) {
    if (argc < 2 || argv == nullptr || argv[1] == nullptr) {
        return report_failure("invalid update invocation");
    }
    const std::string_view mode{argv[1]};
    if (mode == "update") {
        return run_public_update();
    }
#if defined(_WIN32)
    if (mode == "--kasumi-update-helper") {
        return run_windows_wait_helper(argc, argv);
    }
#else
    if (mode == "--kasumi-update-install") {
        return run_linux_install_helper(argc, argv);
    }
#endif
    return report_failure("unknown internal update mode");
}

} // namespace kasumi::cli::update
