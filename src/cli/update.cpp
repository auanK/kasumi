#include "cli/update.hpp"

#include "cli/i18n.hpp"
#include "platform/durability.hpp"
#include "platform/path.hpp"
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
#include <limits>
#include <nlohmann/json.hpp>
#include <print>
#include <reproc++/run.hpp>
#include <set>
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
#include <bcrypt.h>
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
constexpr std::array<std::string_view, 8> LINUX_SYSTEM_TOOLS{
    "curl", "sha256sum", "tar", "dpkg-query", "rpm", "pacman", "apk", "pkexec"};
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

bool trusted_canonical_path(const std::filesystem::path& path,
                            bool final_directory) {
    std::error_code error;
    if (!path.is_absolute() || path.lexically_normal() != path) {
        return false;
    }
    struct stat status{};
    if (::lstat("/", &status) != 0 || !trusted_root_stat(status, true)) {
        return false;
    }
    auto current = std::filesystem::path{"/"};
    const auto components = path.relative_path();
    for (auto iterator = components.begin(); iterator != components.end();
         ++iterator) {
        if (*iterator == "." || *iterator == ".." || iterator->empty()) {
            return false;
        }
        current /= *iterator;
        if (::lstat(current.c_str(), &status) != 0 ||
            !trusted_root_stat(status,
                               std::next(iterator) != components.end() ||
                                   final_directory)) {
            return false;
        }
    }
    return true;
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
    if (S_ISLNK(status.st_mode) && status.st_uid != 0) {
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

LinuxEnvironment linux_base_environment(bool include_proxy = false) {
    LinuxEnvironment environment{
        {"PATH", linux_trusted_path_value()}, {"LANG", "C"}, {"LC_ALL", "C"}};
    if (include_proxy && ::geteuid() != 0) {
        for (const auto* name : {"http_proxy",
                                 "https_proxy",
                                 "HTTP_PROXY",
                                 "HTTPS_PROXY",
                                 "all_proxy",
                                 "ALL_PROXY",
                                 "no_proxy",
                                 "NO_PROXY"}) {
            const char* value = std::getenv(name);
            if (safe_environment_value(value, 4096)) {
                environment.emplace_back(name, value);
            }
        }
    }
    return environment;
}

LinuxEnvironment linux_pkexec_environment() {
    auto environment = linux_base_environment();
    for (const auto* name : {"DISPLAY",
                             "WAYLAND_DISPLAY",
                             "XAUTHORITY",
                             "DBUS_SESSION_BUS_ADDRESS",
                             "XDG_RUNTIME_DIR"}) {
        const char* value = std::getenv(name);
        if (safe_environment_value(value, 4096)) {
            environment.emplace_back(name, value);
        }
    }
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

bool valid_sha256(std::string_view value) noexcept {
    return value.size() == 64 && std::ranges::all_of(value, [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f') ||
                      (character >= 'A' && character <= 'F');
           });
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

std::expected<ProcessResult, std::string>
run_capture(const std::vector<std::string>& arguments,
            std::size_t output_limit = PROCESS_OUTPUT_LIMIT,
            std::size_t error_limit = 8192) {
    if (arguments.empty()) {
        return std::unexpected("process command is empty");
    }
    auto child_arguments = arguments;
    reproc::options options;
    options.redirect.out.type = reproc::redirect::pipe;
    options.redirect.err.type = reproc::redirect::pipe;
    options.stop = reproc::stop_actions{
        {reproc::stop::wait, reproc::milliseconds{300000}},
        {reproc::stop::terminate, reproc::milliseconds{1000}},
        {reproc::stop::kill, reproc::milliseconds{1000}},
    };
#if defined(__linux__)
    const auto tool = resolve_linux_system_tool(arguments.front());
    if (!tool) {
        return std::unexpected(tool.error());
    }
    child_arguments.front() = platform::path::to_utf8(*tool);
    auto environment = linux_base_environment(arguments.front() == "curl");
    options.env.behavior = reproc::env::empty;
    options.env.extra = environment;
    options.working_directory = "/";
#endif
    CappedSink output{.limit = output_limit};
    CappedSink error_output{.limit = error_limit};
    const auto [exit_code, error] = reproc::run(
        reproc::arguments{child_arguments}, options, output, error_output);
    if (error) {
        return std::unexpected("process failed: " + error.message());
    }
    return ProcessResult{.exit_code = exit_code,
                         .output = std::move(output.value),
                         .error_output = std::move(error_output.value)};
}

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
    options.env.behavior = reproc::env::empty;
    options.env.extra = environment;
    options.working_directory = "/";
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

std::expected<std::string, std::string>
read_limited_file(const std::filesystem::path& path, std::size_t limit) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || !std::filesystem::is_regular_file(status)) {
        return std::unexpected("download did not produce a regular file");
    }
    const auto size = std::filesystem::file_size(path, error);
    if (error || size > limit) {
        return std::unexpected("download exceeds the permitted size");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::unexpected("could not read downloaded file");
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    if (size != 0 &&
        !input.read(result.data(), static_cast<std::streamsize>(size))) {
        return std::unexpected("download was incomplete");
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

std::optional<std::string> header_location(const std::filesystem::path& path) {
    auto headers = read_limited_file(path, 64U * 1024U);
    if (!headers) {
        return std::nullopt;
    }
    std::optional<std::string> location;
    std::istringstream input{*headers};
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        constexpr std::string_view prefix = "location:";
        if (line.size() >= prefix.size() &&
            lower_ascii(std::string_view{line}.substr(0, prefix.size())) ==
                prefix) {
            std::string_view value{line};
            value.remove_prefix(prefix.size());
            while (!value.empty() &&
                   (value.front() == ' ' || value.front() == '\t')) {
                value.remove_prefix(1);
            }
            location = std::string{value};
        }
    }
    return location;
}

#if defined(_WIN32)

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
    for (int redirect = 0; redirect <= 5; ++redirect) {
        const auto parts = parse_https_url(url);
        if (!parts || !(api_request ? allowed_api_host(parts->host)
                                    : allowed_download_host(parts->host))) {
            return std::unexpected(
                "download URL is outside the GitHub allowlist");
        }
        int status = 0;
        auto result = winhttp_location(url, maximum_bytes, destination, status);
        if (!result) {
            std::error_code ignored;
            std::filesystem::remove(destination, ignored);
            return std::unexpected(result.error());
        }
        if (!result->empty()) {
            const auto next = parse_https_url(*result);
            if (api_request || !next || !allowed_download_host(next->host) ||
                redirect == 5) {
                return std::unexpected("GitHub redirect was rejected");
            }
            url = std::move(*result);
            continue;
        }
        return {};
    }
    return std::unexpected("too many GitHub redirects");
}

#else

std::expected<void, std::string>
download_url(std::string url,
             const std::filesystem::path& destination,
             std::size_t maximum_bytes,
             bool api_request,
             const platform::Workspace& workspace) {
    const auto header_path =
        platform::workspace_file(workspace, "http-headers");
    if (header_path.empty()) {
        return std::unexpected("could not allocate HTTP header file");
    }
    for (int redirect = 0; redirect <= 5; ++redirect) {
        const auto parts = parse_https_url(url);
        if (!parts || !(api_request ? allowed_api_host(parts->host)
                                    : allowed_download_host(parts->host))) {
            return std::unexpected(
                "download URL is outside the GitHub allowlist");
        }
        std::error_code ignored;
        std::filesystem::remove(destination, ignored);
        std::filesystem::remove(header_path, ignored);
        auto response = run_capture({"curl",
                                     "--disable",
                                     "--silent",
                                     "--show-error",
                                     "--globoff",
                                     "--proto",
                                     "=https",
                                     "--connect-timeout",
                                     "15",
                                     "--max-time",
                                     api_request ? "30" : "180",
                                     "--max-filesize",
                                     std::to_string(maximum_bytes),
                                     "--dump-header",
                                     platform::path::to_utf8(header_path),
                                     "--output",
                                     platform::path::to_utf8(destination),
                                     "--write-out",
                                     "%{http_code}\n",
                                     url});
        if (!response || response->exit_code != 0) {
            std::filesystem::remove(destination, ignored);
            return std::unexpected(response ? (response->error_output.empty()
                                                   ? "HTTPS download failed"
                                                   : response->error_output)
                                            : response.error());
        }
        int status = 0;
        const auto [end, parse_error] =
            std::from_chars(response->output.data(),
                            response->output.data() + response->output.size(),
                            status);
        if (parse_error != std::errc{} || end == response->output.data()) {
            return std::unexpected("could not read HTTP response status");
        }
        if (status >= 300 && status < 400) {
            const auto location = header_location(header_path);
            const auto next =
                location ? parse_https_url(*location) : std::nullopt;
            if (api_request || !location || !next ||
                !allowed_download_host(next->host) || redirect == 5) {
                return std::unexpected("GitHub redirect was rejected");
            }
            url = *location;
            continue;
        }
        if (status != 200) {
            std::filesystem::remove(destination, ignored);
            return std::unexpected("GitHub returned HTTP " +
                                   std::to_string(status));
        }
        auto body = read_limited_file(destination, maximum_bytes);
        if (!body) {
            std::filesystem::remove(destination, ignored);
            return std::unexpected(body.error());
        }
        return {};
    }
    return std::unexpected("too many GitHub redirects");
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
    if (!response) {
        return std::unexpected(response.error());
    }
    return response;
}

std::expected<std::string, std::string>
sha256_file_impl(const std::filesystem::path& path) {
#if defined(_WIN32)
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        return std::unexpected("could not initialize SHA-256");
    }
    DWORD object_size = 0;
    DWORD result_size = 0;
    if (BCryptGetProperty(algorithm,
                          BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&object_size),
                          sizeof(object_size),
                          &result_size,
                          0) < 0 ||
        object_size == 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return std::unexpected("could not initialize SHA-256 hash state");
    }
    std::vector<UCHAR> object(object_size);
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(
            algorithm, &hash, object.data(), object_size, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return std::unexpected("could not create SHA-256 hash state");
    }
    std::ifstream input(path, std::ios::binary);
    std::array<UCHAR, 65536> buffer{};
    bool failed = !input;
    while (!failed && input) {
        input.read(reinterpret_cast<char*>(buffer.data()),
                   static_cast<std::streamsize>(buffer.size()));
        const auto read = input.gcount();
        if (read > 0 &&
            BCryptHashData(hash, buffer.data(), static_cast<ULONG>(read), 0) <
                0) {
            failed = true;
        }
    }
    std::array<UCHAR, 32> digest{};
    if (failed ||
        BCryptFinishHash(
            hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return std::unexpected("could not hash downloaded package");
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto byte : digest) {
        result.push_back(hex[byte >> 4U]);
        result.push_back(hex[byte & 0x0fU]);
    }
    return result;
#else
    auto result =
        run_capture({"sha256sum", "--", platform::path::to_utf8(path)});
    if (!result || result->exit_code != 0 || result->output.size() < 64) {
        return std::unexpected("could not hash downloaded package");
    }
    const std::string_view hash{result->output.data(), 64};
    if (!valid_sha256(hash)) {
        return std::unexpected("SHA-256 tool returned an invalid digest");
    }
    return lower_ascii(hash);
#endif
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
            std::error_code error;
            auto resolved = std::filesystem::canonical(
                std::filesystem::path{std::wstring_view{buffer.data(), length}},
                error);
            if (error || !std::filesystem::is_regular_file(resolved, error) ||
                error) {
                return std::nullopt;
            }
            return resolved;
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
            std::error_code error;
            auto resolved = std::filesystem::canonical(
                std::filesystem::path{std::string_view{
                    buffer.data(), static_cast<std::size_t>(length)}},
                error);
            if (error || !std::filesystem::is_regular_file(resolved, error) ||
                error) {
                return std::nullopt;
            }
            return resolved;
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
#if defined(_WIN32)
    const auto listing =
        run_capture({"tar", "-tvf", platform::path::to_utf8(archive)});
#else
    const auto listing =
        run_capture({"tar", "-tvzf", platform::path::to_utf8(archive)});
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
#if defined(_WIN32)
    const auto extracted = run_capture({"tar",
                                        "-xf",
                                        platform::path::to_utf8(archive),
                                        "-C",
                                        platform::path::to_utf8(destination),
                                        "--",
                                        package.executable,
                                        "LICENSE",
                                        "THIRD_PARTY_NOTICES.md"});
#else
    const auto extracted = run_capture({"tar",
                                        "-xzf",
                                        platform::path::to_utf8(archive),
                                        "-C",
                                        platform::path::to_utf8(destination),
                                        "--no-same-owner",
                                        "--no-same-permissions",
                                        "--",
                                        package.executable,
                                        "LICENSE",
                                        "THIRD_PARTY_NOTICES.md"});
#endif
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
    auto bytes = read_limited_file(executable, EXECUTABLE_LIMIT);
    if (!bytes || bytes->size() < 64) {
        return std::unexpected("package executable is incomplete");
    }
#if defined(_WIN32)
    if ((*bytes)[0] != 'M' || (*bytes)[1] != 'Z' || bytes->size() < 256) {
        return std::unexpected("package is not a Windows executable");
    }
    std::uint32_t pe_offset = 0;
    std::memcpy(&pe_offset, bytes->data() + 0x3c, sizeof(pe_offset));
    if (pe_offset > bytes->size() - 6 ||
        bytes->compare(pe_offset, 4, "PE\0\0", 4) != 0 ||
        static_cast<unsigned char>((*bytes)[pe_offset + 4]) != 0x64 ||
        static_cast<unsigned char>((*bytes)[pe_offset + 5]) != 0x86) {
        return std::unexpected("package executable is not x86_64 Windows");
    }
#else
    if (static_cast<unsigned char>((*bytes)[0]) != 0x7f || (*bytes)[1] != 'E' ||
        (*bytes)[2] != 'L' || (*bytes)[3] != 'F' ||
        static_cast<unsigned char>((*bytes)[4]) != 2 ||
        static_cast<unsigned char>((*bytes)[5]) != 1 ||
        static_cast<unsigned char>((*bytes)[18]) != 62) {
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
                              .sha256 = *executable_hash};
}

} // namespace

std::expected<std::string, std::string>
sha256_file(const std::filesystem::path& path) {
    return sha256_file_impl(path);
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
    for (const auto& [left_value, right_value] :
         {std::pair{left.major, right.major},
          std::pair{left.minor, right.minor},
          std::pair{left.patch, right.patch}}) {
        if (left_value < right_value) {
            return std::strong_ordering::less;
        }
        if (left_value > right_value) {
            return std::strong_ordering::greater;
        }
    }
    if (left.prerelease.empty() != right.prerelease.empty()) {
        return left.prerelease.empty() ? std::strong_ordering::greater
                                       : std::strong_ordering::less;
    }
    for (std::size_t index = 0;
         index < std::min(left.prerelease.size(), right.prerelease.size());
         ++index) {
        const auto compared =
            compare_identifier(left.prerelease[index], right.prerelease[index]);
        if (compared != 0) {
            return compared;
        }
    }
    if (left.prerelease.size() < right.prerelease.size()) {
        return std::strong_ordering::less;
    }
    if (left.prerelease.size() > right.prerelease.size()) {
        return std::strong_ordering::greater;
    }
    return std::strong_ordering::equal;
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
        const auto url = "https://api.github.com/repos/" +
                         std::string{GITHUB_REPOSITORY} +
                         "/releases?per_page=100&page=" + std::to_string(page);
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

bool valid_archive_listing(std::string_view listing,
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
        auto entry = listing.substr(begin, end - begin);
        if (!entry.empty() && entry.back() == '\r') {
            entry.remove_suffix(1);
        }
        if (entry.empty() ||
            (!required.contains(entry) && !optional.contains(entry)) ||
            !found.insert(entry).second) {
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

bool official_asset_url(std::string_view tag,
                        std::string_view name,
                        std::string_view url) {
    if (!tag.starts_with('v') || !parse_version(tag) || name.empty() ||
        name.find_first_of("/\\?#\r\n") != std::string_view::npos) {
        return false;
    }
    return url == "https://github.com/" + std::string{GITHUB_REPOSITORY} +
                      "/releases/download/" + std::string{tag} + "/" +
                      std::string{name};
}

namespace {

std::expected<std::string, std::string> new_identifier() {
    auto id = platform::random::hex_id();
    if (!id) {
        return std::unexpected(id.error());
    }
    return *id;
}

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
    const auto target_status = std::filesystem::status(target, error);
    if (error) {
        return std::unexpected(filesystem_failure(
            "could not read installed executable permissions", error));
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
    auto id = new_identifier();
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
    if (!std::filesystem::copy_file(
            prepared, staged, std::filesystem::copy_options::none, error) ||
        error) {
        return std::unexpected(filesystem_failure(
            "could not prepare executable beside installation", error));
    }
#if !defined(_WIN32)
    struct stat original_stat{};
    struct stat staged_stat{};
    if (::stat(target.c_str(), &original_stat) != 0 ||
        ::stat(staged.c_str(), &staged_stat) != 0) {
        const std::error_code status_error{errno, std::generic_category()};
        return std::unexpected(filesystem_failure(
            "could not inspect executable ownership", status_error));
    }
    if ((staged_stat.st_uid != original_stat.st_uid ||
         staged_stat.st_gid != original_stat.st_gid) &&
        ::chown(staged.c_str(),
                staged_stat.st_uid == original_stat.st_uid
                    ? static_cast<uid_t>(-1)
                    : original_stat.st_uid,
                staged_stat.st_gid == original_stat.st_gid
                    ? static_cast<gid_t>(-1)
                    : original_stat.st_gid) != 0) {
        const std::error_code owner_error{errno, std::generic_category()};
        return std::unexpected(filesystem_failure(
            "could not preserve executable ownership", owner_error));
    }
    std::filesystem::permissions(staged,
                                 target_status.permissions(),
                                 std::filesystem::perm_options::replace,
                                 error);
    if (error) {
        return std::unexpected(filesystem_failure(
            "could not preserve executable permissions", error));
    }
#endif
    const auto staged_hash = hash_file(staged);
    if (!staged_hash ||
        lower_ascii(*staged_hash) != lower_ascii(expected_sha256)) {
        return std::unexpected(install_failure(
            staged_hash ? "staged executable changed before replacement"
                        : staged_hash.error()));
    }
    auto synced = platform::durability::sync_file(staged);
    if (!synced) {
        return std::unexpected(install_failure(synced.error()));
    }
    if (!std::filesystem::copy_file(
            target, backup, std::filesystem::copy_options::none, error) ||
        error) {
        return std::unexpected(filesystem_failure(
            "could not keep a recovery copy of the installed executable",
            error));
    }
#if !defined(_WIN32)
    struct stat backup_stat{};
    if (::stat(backup.c_str(), &backup_stat) != 0) {
        const std::error_code status_error{errno, std::generic_category()};
        return std::unexpected(filesystem_failure(
            "could not inspect recovery copy ownership", status_error));
    }
    if ((backup_stat.st_uid != original_stat.st_uid ||
         backup_stat.st_gid != original_stat.st_gid) &&
        ::chown(backup.c_str(),
                backup_stat.st_uid == original_stat.st_uid
                    ? static_cast<uid_t>(-1)
                    : original_stat.st_uid,
                backup_stat.st_gid == original_stat.st_gid
                    ? static_cast<gid_t>(-1)
                    : original_stat.st_gid) != 0) {
        const std::error_code owner_error{errno, std::generic_category()};
        return std::unexpected(filesystem_failure(
            "could not preserve recovery copy ownership", owner_error));
    }
    std::filesystem::permissions(backup,
                                 target_status.permissions(),
                                 std::filesystem::perm_options::replace,
                                 error);
    if (error) {
        return std::unexpected(filesystem_failure(
            "could not preserve recovery copy permissions", error));
    }
#endif
    const auto backup_hash = hash_file(backup);
    if (!backup_hash || *backup_hash != *original_hash) {
        return std::unexpected(install_failure(
            backup_hash ? "recovery copy does not match installed executable"
                        : backup_hash.error()));
    }
    synced = platform::durability::sync_file(backup);
    if (!synced) {
        return std::unexpected(install_failure(synced.error()));
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
    synced = platform::durability::sync_parent_directory(target);
    if (!synced) {
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
std::expected<void, std::string>
validate_windows_workspace_acl_impl(const std::filesystem::path& root) {
    auto path = root.native();
    PACL dacl = nullptr;
    PSID security_owner = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const auto query = GetNamedSecurityInfoW(path.data(),
                                             SE_FILE_OBJECT,
                                             DACL_SECURITY_INFORMATION |
                                                 OWNER_SECURITY_INFORMATION,
                                             &security_owner,
                                             nullptr,
                                             &dacl,
                                             nullptr,
                                             &descriptor);
    if (query != ERROR_SUCCESS || descriptor == nullptr || dacl == nullptr) {
        if (descriptor != nullptr) {
            LocalFree(descriptor);
        }
        return std::unexpected("could not verify update workspace permissions");
    }
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    const bool protected_dacl =
        GetSecurityDescriptorControl(descriptor, &control, &revision) != 0 &&
        (control & SE_DACL_PROTECTED) != 0;

    bool valid = protected_dacl;
    valid = valid && security_owner != nullptr;
    alignas(DWORD) std::array<std::byte, SECURITY_MAX_SID_SIZE>
        system_sid_storage{};
    DWORD system_sid_size = static_cast<DWORD>(system_sid_storage.size());
    valid = valid && CreateWellKnownSid(WinLocalSystemSid,
                                        nullptr,
                                        system_sid_storage.data(),
                                        &system_sid_size) != 0;
    alignas(DWORD) std::array<std::byte, SECURITY_MAX_SID_SIZE>
        admin_sid_storage{};
    DWORD admin_sid_size = static_cast<DWORD>(admin_sid_storage.size());
    valid = valid && CreateWellKnownSid(WinBuiltinAdministratorsSid,
                                        nullptr,
                                        admin_sid_storage.data(),
                                        &admin_sid_size) != 0;
    ACL_SIZE_INFORMATION acl_info{};
    valid = valid &&
            GetAclInformation(
                dacl, &acl_info, sizeof(acl_info), AclSizeInformation) != 0 &&
            acl_info.AceCount == 3;
    bool has_workspace_user = false;
    bool has_system = false;
    bool has_admin_read = false;
    PSID workspace_user = nullptr;
    for (DWORD index = 0; valid && index < acl_info.AceCount; ++index) {
        void* raw_ace = nullptr;
        if (!GetAce(dacl, index, &raw_ace) || raw_ace == nullptr) {
            valid = false;
            break;
        }
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) {
            valid = false;
            break;
        }
        auto* sid = reinterpret_cast<PSID>(&ace->SidStart);
        if (EqualSid(sid, system_sid_storage.data())) {
            has_system = ace->Mask == FILE_ALL_ACCESS;
        } else if (EqualSid(sid, admin_sid_storage.data())) {
            has_admin_read =
                ace->Mask == (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) &&
                ace->Header.AceFlags ==
                    (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);
        } else if (ace->Mask == FILE_ALL_ACCESS && !has_workspace_user) {
            has_workspace_user = true;
            workspace_user = sid;
        } else {
            valid = false;
        }
    }
    HANDLE token = nullptr;
    valid = valid &&
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != 0;
    std::vector<std::byte> token_data;
    if (valid) {
        DWORD required = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &required);
        token_data.resize(required);
        valid =
            required != 0 &&
            GetTokenInformation(
                token, TokenUser, token_data.data(), required, &required) != 0;
    }
    if (token != nullptr) {
        CloseHandle(token);
    }
    const auto* current_user =
        valid ? reinterpret_cast<const TOKEN_USER*>(token_data.data())
              : nullptr;
    const bool current_is_owner =
        current_user != nullptr && workspace_user != nullptr &&
        EqualSid(current_user->User.Sid, workspace_user);
    BOOL current_is_admin = FALSE;
    if (valid && !current_is_owner) {
        BOOL is_member = FALSE;
        current_is_admin = CheckTokenMembership(nullptr,
                                                admin_sid_storage.data(),
                                                &is_member) != 0 &&
                           is_member;
    }
    const bool owner_is_expected =
        security_owner != nullptr && workspace_user != nullptr &&
        (EqualSid(security_owner, workspace_user) ||
         EqualSid(security_owner, admin_sid_storage.data()));
    LocalFree(descriptor);
    if (!valid || !owner_is_expected || !has_workspace_user || !has_system ||
        !has_admin_read || (!current_is_owner && !current_is_admin)) {
        return std::unexpected("update workspace ACL does not preserve owner "
                               "privacy and administrator read access");
    }
    return {};
}

std::expected<void, std::string>
grant_windows_admin_process_query_access(HANDLE process) {
    PACL old_acl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const auto query = GetSecurityInfo(process,
                                       SE_KERNEL_OBJECT,
                                       DACL_SECURITY_INFORMATION,
                                       nullptr,
                                       nullptr,
                                       &old_acl,
                                       nullptr,
                                       &descriptor);
    if (query != ERROR_SUCCESS || descriptor == nullptr || old_acl == nullptr) {
        if (descriptor != nullptr) {
            LocalFree(descriptor);
        }
        return std::unexpected(
            "could not inspect installer process permissions");
    }
    alignas(DWORD) std::array<std::byte, SECURITY_MAX_SID_SIZE> admin_sid{};
    DWORD sid_size = static_cast<DWORD>(admin_sid.size());
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid,
                            nullptr,
                            admin_sid.data(),
                            &sid_size)) {
        LocalFree(descriptor);
        return std::unexpected("could not identify Windows administrators");
    }
    EXPLICIT_ACCESSW access{};
    access.grfAccessPermissions =
        PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(admin_sid.data());
    PACL new_acl = nullptr;
    const auto merged = SetEntriesInAclW(1, &access, old_acl, &new_acl);
    LocalFree(descriptor);
    if (merged != ERROR_SUCCESS || new_acl == nullptr) {
        if (new_acl != nullptr) {
            LocalFree(new_acl);
        }
        return std::unexpected(
            "could not grant administrator query access to installer process");
    }
    const auto updated = SetSecurityInfo(process,
                                         SE_KERNEL_OBJECT,
                                         DACL_SECURITY_INFORMATION,
                                         nullptr,
                                         nullptr,
                                         new_acl,
                                         nullptr);
    LocalFree(new_acl);
    if (updated != ERROR_SUCCESS) {
        return std::unexpected("could not secure installer process handoff");
    }
    return {};
}
#endif

#if defined(_WIN32)
bool windows_entry_is_not_reparse_point(const std::filesystem::path& path) {
    HANDLE handle =
        CreateFileW(path.c_str(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    const bool valid =
        GetFileInformationByHandleEx(
            handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) !=
            0 &&
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
    CloseHandle(handle);
    return valid;
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
    if (!root.is_absolute() || !windows_entry_is_not_reparse_point(root)) {
        return std::unexpected(
            "update staging directory cannot be resolved safely");
    }
    auto secure = validate_windows_workspace_acl_impl(root);
    if (!secure) {
        return secure;
    }
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
        const char* original_uid = std::getenv("PKEXEC_UID");
        if (original_uid == nullptr) {
            original_uid = std::getenv("SUDO_UID");
        }
        uid_t expected_uid = 0;
        if (original_uid == nullptr) {
            return std::unexpected("could not validate update staging owner");
        }
        const auto [uid_end, uid_error] = std::from_chars(
            original_uid,
            original_uid + std::char_traits<char>::length(original_uid),
            expected_uid);
        if (uid_error != std::errc{} || *uid_end != '\0' ||
            workspace_stat.st_uid != expected_uid) {
            return std::unexpected(
                "update staging directory has an unexpected owner");
        }
    }
#endif
    return {};
}

[[maybe_unused]] std::expected<PreparedExecutable, std::string>
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
    platform::Workspace workspace{
        .root = root / platform::path::from_utf8(extraction_name)};
    if (!std::filesystem::create_directory(workspace.root, error) || error) {
        return std::unexpected(
            "could not create package verification directory");
    }
#if !defined(_WIN32)
    std::filesystem::permissions(workspace.root,
                                 std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace,
                                 error);
    if (error) {
        platform::cleanup_workspace(workspace);
        return std::unexpected(
            "could not secure package verification directory");
    }
#endif
    auto prepared =
        prepare_verified_package(archive, checksum, package, workspace);
    if (!prepared) {
        platform::cleanup_workspace(workspace);
        return std::unexpected(prepared.error());
    }
    return *prepared;
}

std::optional<std::string> release_asset_url(const Release& release,
                                             std::string_view name);

[[maybe_unused]] std::expected<std::string, std::string>
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
    const ApiGet get =
        [&](std::string_view url,
            std::size_t limit) -> std::expected<HttpResponse, std::string> {
        auto body = get_text(std::string{url}, limit, workspace);
        if (!body) {
            return std::unexpected(body.error());
        }
        return HttpResponse{.status = 200, .body = std::move(*body)};
    };
    auto releases = fetch_releases(get);
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

std::optional<std::filesystem::path> find_program(std::string_view name) {
#if defined(_WIN32)
    (void)name;
    return std::nullopt;
#elif defined(__linux__)
    const auto resolved = resolve_linux_system_tool(name);
    return resolved ? std::optional<std::filesystem::path>{*resolved}
                    : std::nullopt;
#else
    const char* path_value = std::getenv("PATH");
    if (path_value == nullptr) {
        return std::nullopt;
    }
    for (const auto directory : split(path_value, ':')) {
        const auto candidate =
            std::filesystem::path{directory} / platform::path::from_utf8(name);
        if (::access(candidate.c_str(), X_OK) == 0) {
            return candidate;
        }
    }
    return std::nullopt;
#endif
}

#if defined(__linux__)
std::expected<std::string, std::string>
curl_checksum_as_user(std::string_view url, uid_t uid) {
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
    const std::string address{url};
    const std::string max_size = "4096";
    std::vector<std::string> argument_values{
        curl->string(), "--disable",    "--fail",
        "--location",   "--silent",     "--show-error",
        "--proto",      "=https",       "--proto-redir",
        "=https",       "--max-redirs", "5",
        "--max-time",   "30",           "--max-filesize",
        max_size,       "--write-out",  "\n%{url_effective}",
        "--url",        address};
    std::vector<char*> arguments;
    arguments.reserve(argument_values.size() + 1);
    for (auto& argument : argument_values) {
        arguments.push_back(argument.data());
    }
    arguments.push_back(nullptr);
    std::vector<std::string> environment{"PATH=" + linux_trusted_path_value(),
                                         "HOME=" + home,
                                         "LANG=C",
                                         "LC_ALL=C"};
    for (const auto* name : {"http_proxy",
                             "https_proxy",
                             "HTTP_PROXY",
                             "HTTPS_PROXY",
                             "all_proxy",
                             "ALL_PROXY",
                             "no_proxy",
                             "NO_PROXY"}) {
        if (const char* value = std::getenv(name); value != nullptr) {
            environment.push_back(std::string{name} + "=" + value);
        }
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
        return std::unexpected("could not start unprivileged checksum request");
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
    std::array<char, 2048> buffer{};
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
            8192U - std::min<std::size_t>(8192U, output.size())) {
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
        return std::unexpected(
            oversized ? "checksum response exceeds the permitted size"
                      : "unprivileged checksum request failed");
    }
    const auto separator = output.rfind('\n');
    if (separator == std::string::npos) {
        return std::unexpected("checksum response has no final URL");
    }
    const auto final_url = std::string_view{output}.substr(separator + 1);
    const auto final_parts = parse_https_url(final_url);
    if (!final_parts || !allowed_download_host(final_parts->host)) {
        return std::unexpected("checksum redirect left the GitHub allowlist");
    }
    return output.substr(0, separator);
}

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

std::string language_code() {
    return i18n::current_language() == i18n::Language::Portuguese ? "pt-BR"
                                                                  : "en";
}

void select_helper_language(std::string_view language) {
    i18n::set_language(language == "pt-BR" ? i18n::Language::Portuguese
                                           : i18n::Language::English);
}

int report_failure(std::string_view detail) {
    std::println("{}", i18n::format(i18n::Key::UpdateFailed, detail));
    return 1;
}

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

std::expected<void, std::string>
install_with_elevation(const std::filesystem::path& executable,
                       const std::filesystem::path& archive,
                       std::string_view tag,
                       std::string_view language) {
#if defined(_WIN32)
    (void)executable;
    (void)archive;
    (void)tag;
    (void)language;
    return std::unexpected("Windows installation helper was not started");
#elif defined(__linux__)
    const auto pkexec = find_program("pkexec");
    const auto sudo = find_program("sudo");
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
            auto command =
                std::vector<std::string>{platform::path::to_utf8(*pkexec),
                                         self,
                                         "--kasumi-update-install",
                                         platform::path::to_utf8(archive),
                                         std::string{tag},
                                         std::string{language}};
            const auto tool = resolve_linux_system_tool("pkexec");
            if (!tool) {
                return LinuxElevationResult{LinuxElevationState::Failed,
                                            tool.error()};
            }
            command.front() = platform::path::to_utf8(*tool);
            reproc::options options;
            auto environment = linux_pkexec_environment();
            options.env.behavior = reproc::env::empty;
            options.env.extra = environment;
            options.working_directory = "/";
            options.redirect.in.type = reproc::redirect::parent;
            options.redirect.out.type = reproc::redirect::parent;
            options.redirect.err.type = reproc::redirect::pipe;
            options.stop = reproc::stop_actions{
                {reproc::stop::wait, reproc::milliseconds{300000}},
                {reproc::stop::terminate, reproc::milliseconds{1000}},
                {reproc::stop::kill, reproc::milliseconds{1000}},
            };
            CappedSink error_output{.limit = 8192};
            const auto [exit_code, error] =
                reproc::run(reproc::arguments{command},
                            options,
                            reproc::sink::null,
                            error_output);
            if (error) {
                return LinuxElevationResult{LinuxElevationState::Failed,
                                            "could not run pkexec: " +
                                                error.message()};
            }
            return classify_linux_pkexec_result(exit_code, error_output.value);
        }}
               : LinuxElevationAttempt{},
        sudo ? LinuxElevationAttempt{[&] {
            const auto tool = resolve_linux_system_tool("sudo");
            if (!tool) {
                return LinuxElevationResult{LinuxElevationState::Failed,
                                            tool.error()};
            }
            const auto elevated =
                run_inherited({platform::path::to_utf8(*tool),
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
    const auto sudo = find_program("sudo");
    if (!sudo || ::isatty(STDIN_FILENO) == 0) {
        return std::unexpected(
            i18n::format(i18n::Key::UpdateElevationUnavailable,
                         "interactive sudo is unavailable"));
    }
    const auto self = platform::path::to_utf8(executable);
    return run_inherited({platform::path::to_utf8(*sudo),
                          "--",
                          self,
                          "--kasumi-update-install",
                          platform::path::to_utf8(archive),
                          std::string{tag},
                          std::string{language}});
#endif
}

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

struct ScopedWindowsHandle {
    HANDLE value = nullptr;
    ~ScopedWindowsHandle() {
        if (value != nullptr && value != INVALID_HANDLE_VALUE) {
            CloseHandle(value);
        }
    }
};

std::optional<DWORD> windows_parent_process_id(DWORD process_id) {
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::optional<DWORD> result;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == process_id) {
                result = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

bool windows_path_has_no_reparse_points(const std::filesystem::path& path) {
    const auto check = [](const std::filesystem::path& item) {
        HANDLE handle = CreateFileW(
            item.c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            return false;
        }
        FILE_ATTRIBUTE_TAG_INFO info{};
        const bool valid =
            GetFileInformationByHandleEx(
                handle, FileAttributeTagInfo, &info, sizeof(info)) != 0 &&
            (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
        CloseHandle(handle);
        return valid;
    };
    if (!path.is_absolute()) {
        return false;
    }
    auto current = path.root_path();
    if (current.empty() || !check(current)) {
        return false;
    }
    for (const auto& component : path.relative_path()) {
        if (component.empty() || component == L".") {
            continue;
        }
        if (component == L"..") {
            return false;
        }
        current /= component;
        if (!check(current)) {
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
    for (const auto byte : identity.file_id) {
        result.push_back(hex[byte >> 4U]);
        result.push_back(hex[byte & 0x0fU]);
    }
    return result;
}

std::optional<WindowsFileIdentity>
parse_windows_identity(std::string_view value) {
    if (value.size() != 48 || !std::ranges::all_of(value, [](char character) {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'f') ||
                   (character >= 'A' && character <= 'F');
        })) {
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

std::optional<std::wstring>
kasumi_product_version(const std::filesystem::path& path) {
    DWORD ignored = 0;
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
    if (size == 0 || size > 1024U * 1024U) {
        return std::nullopt;
    }
    std::vector<std::byte> data(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, data.data())) {
        return std::nullopt;
    }
    void* value = nullptr;
    UINT length = 0;
    if (!VerQueryValueW(data.data(),
                        L"\\StringFileInfo\\040904b0\\ProductVersion",
                        &value,
                        &length) ||
        value == nullptr || length <= 1) {
        return std::nullopt;
    }
    return std::wstring{static_cast<const wchar_t*>(value), length - 1};
}

std::expected<void, std::string>
launch_elevated_windows(const std::filesystem::path& helper,
                        const std::filesystem::path& archive,
                        std::string_view version,
                        std::string_view language,
                        DWORD original_process_id,
                        const WindowsFileIdentity& target_identity) {
    auto version_w = widen_ascii(version);
    auto language_w = widen_ascii(language);
    const auto identity_w = widen_ascii(windows_identity_text(target_identity));
    if (!version_w || !language_w || !identity_w) {
        return std::unexpected("invalid installer handoff arguments");
    }
    const auto parameters =
        join_windows_arguments({L"--kasumi-update-elevated",
                                archive.wstring(),
                                *version_w,
                                *language_w,
                                std::to_wstring(GetCurrentProcessId()),
                                std::to_wstring(original_process_id),
                                *identity_w});
    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask =
        SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_NO_CONSOLE;
    info.lpVerb = L"runas";
    info.lpFile = helper.c_str();
    info.lpParameters = parameters.c_str();
    info.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&info)) {
        const DWORD error = GetLastError();
        if (error == ERROR_CANCELLED) {
            return std::unexpected("administrator authorization was cancelled");
        }
        return std::unexpected(
            "could not request Windows administrator privileges");
    }
    if (info.hProcess == nullptr) {
        return std::unexpected(
            "elevated installer did not return a process handle");
    }
    const DWORD wait = WaitForSingleObject(info.hProcess, INFINITE);
    DWORD exit_code = 1;
    const bool queried = wait == WAIT_OBJECT_0 &&
                         GetExitCodeProcess(info.hProcess, &exit_code) != 0;
    CloseHandle(info.hProcess);
    if (!queried || exit_code != 0) {
        return std::unexpected("elevated installer failed");
    }
    return {};
}

std::expected<void, std::string>
start_windows_helper(const std::filesystem::path& executable,
                     const std::filesystem::path& archive,
                     std::string_view version,
                     const WindowsFileIdentity& target_identity,
                     const platform::Workspace& workspace) {
    auto id = new_identifier();
    if (!id) {
        return std::unexpected(id.error());
    }
    auto process_acl =
        grant_windows_admin_process_query_access(GetCurrentProcess());
    if (!process_acl) {
        return std::unexpected(process_acl.error());
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
    if (!version_w || !language_w || !identity_w ||
        !windows_path_has_no_reparse_points(executable) ||
        !windows_file_identity_matches(executable, target_identity)) {
        std::filesystem::remove(helper, error);
        return std::unexpected("invalid installer handoff arguments");
    }
    const auto command_line =
        join_windows_arguments({helper.wstring(),
                                L"--kasumi-update-helper",
                                archive.wstring(),
                                *version_w,
                                *language_w,
                                std::to_wstring(self_process),
                                *identity_w});
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
    const auto ready_path =
        workspace.root / platform::path::from_utf8("helper-ready");
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

int run_windows_elevated_helper(int argc, char* argv[]) {
    if (argc != 8 || argv[2] == nullptr || argv[3] == nullptr ||
        argv[4] == nullptr || argv[5] == nullptr || argv[6] == nullptr ||
        argv[7] == nullptr) {
        return report_failure("invalid installer handoff");
    }
    select_helper_language(argv[4]);
    DWORD helper_id = 0;
    DWORD original_id = 0;
    const auto [helper_end, helper_error] = std::from_chars(
        argv[5], argv[5] + std::char_traits<char>::length(argv[5]), helper_id);
    const auto [original_end, original_error] =
        std::from_chars(argv[6],
                        argv[6] + std::char_traits<char>::length(argv[6]),
                        original_id);
    const auto expected_identity = parse_windows_identity(argv[7]);
    if (helper_error != std::errc{} || *helper_end != '\0' ||
        original_error != std::errc{} || *original_end != '\0' ||
        !expected_identity || !windows_parent_process_id(helper_id) ||
        windows_parent_process_id(helper_id) != original_id) {
        return report_failure("invalid installer process association");
    }
    HANDLE helper_handle = nullptr;
    const auto parent_path = windows_process_path(helper_id, helper_handle);
    ScopedWindowsHandle keep_helper{helper_handle};
    const auto helper_path = current_executable_path();
    std::error_code parent_error;
    const bool trusted_parent =
        parent_path && helper_path &&
        std::filesystem::equivalent(*parent_path, *helper_path, parent_error) &&
        !parent_error && windows_entry_is_not_reparse_point(*helper_path) &&
        is_kasumi_executable(*helper_path);
    if (!trusted_parent) {
        return report_failure("elevated installer was not started by Kasumi");
    }
    HANDLE original_handle = nullptr;
    const auto target_value =
        windows_process_path(original_id, original_handle);
    ScopedWindowsHandle keep_original{original_handle};
    if (!target_value || !windows_path_has_no_reparse_points(*target_value) ||
        !windows_file_identity_matches(*target_value, *expected_identity) ||
        target_value->filename() != platform::path::from_utf8("kasumi.exe")) {
        return report_failure(
            "original installation identity changed during update handoff");
    }
    const auto target = *target_value;
    const auto archive = platform::path::from_utf8(argv[2]);
    const std::string_view version{argv[3]};
    if (!parse_version(version)) {
        return report_failure("invalid installer release version");
    }
    const auto package = package_names_for_this_platform();
    if (!package) {
        return report_failure(
            "this operating system or architecture is unsupported");
    }
    const auto root = archive.parent_path();
    auto valid_root = validate_staging_root(root);
    std::error_code error;
    const auto archive_size = std::filesystem::file_size(archive, error);
    if (!valid_root ||
        archive.filename() != platform::path::from_utf8(package->archive) ||
        !is_regular_file_without_redirect(archive) || error ||
        archive_size == 0 || archive_size > PACKAGE_LIMIT ||
        !windows_entry_is_not_reparse_point(root) ||
        !windows_file_identity(archive)) {
        return report_failure(
            "update package is outside its protected staging directory");
    }
    std::string manager;
    if (package_managed_installation(target, manager)) {
        return report_failure(
            i18n::format(i18n::Key::UpdateManagedInstallation, manager));
    }
    const auto target_version = kasumi_product_version(target);
    std::optional<std::wstring> helper_version;
    helper_version = kasumi_product_version(*helper_path);
    if (!is_regular_file_without_redirect(target) ||
        !is_kasumi_executable(target) || !target_version || !helper_version ||
        *target_version != *helper_version) {
        return report_failure("installation destination is invalid");
    }
    auto workspace = platform::create_workspace("update-elevated");
    if (!workspace) {
        return report_failure(workspace.error());
    }
    struct WorkspaceCleanup {
        platform::Workspace value;
        ~WorkspaceCleanup() {
            platform::cleanup_workspace(value);
        }
    } cleanup{.value = *workspace};
    auto digest =
        refetch_official_digest(archive, version, *package, *workspace);
    if (!digest) {
        return report_failure(digest.error());
    }
    const auto trusted_archive =
        platform::workspace_file(*workspace, package->archive);
    if (trusted_archive.empty() ||
        !std::filesystem::copy_file(archive,
                                    trusted_archive,
                                    std::filesystem::copy_options::none,
                                    error) ||
        error) {
        return report_failure("could not copy update package into a private "
                              "administrator workspace");
    }
    const auto prepared = prepare_verified_package(
        trusted_archive, *digest, *package, *workspace);
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
    const auto installed = install_prepared_executable(
        prepared->path, target, prepared->sha256, &target_identity_hook);
    if (!installed) {
        return report_failure(installed.error().detail);
    }
    return 0;
}

int run_windows_wait_helper(int argc, char* argv[]) {
    if (argc != 7 || argv[2] == nullptr || argv[3] == nullptr ||
        argv[4] == nullptr || argv[5] == nullptr || argv[6] == nullptr) {
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
    if (!expected_identity ||
        windows_parent_process_id(GetCurrentProcessId()) != parent_id) {
        return report_failure(
            "installer was not started by the original Kasumi process");
    }
    HANDLE parent = nullptr;
    const auto parent_path = windows_process_path(parent_id, parent);
    ScopedWindowsHandle keep_parent{parent};
    if (!parent_path || !is_kasumi_executable(*parent_path) ||
        !windows_path_has_no_reparse_points(*parent_path) ||
        parent_path->filename() != platform::path::from_utf8("kasumi.exe") ||
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
    auto process_acl =
        grant_windows_admin_process_query_access(GetCurrentProcess());
    if (!process_acl) {
        return report_failure(process_acl.error());
    }
    const auto ready = root / platform::path::from_utf8("helper-ready");
    {
        std::ofstream marker(ready, std::ios::binary | std::ios::trunc);
        if (!marker) {
            return report_failure("could not initialize installer handoff");
        }
        marker << "ready";
    }
    struct HandoffCleanup {
        std::filesystem::path root;
        std::filesystem::path helper;
        ~HandoffCleanup() {
            platform::cleanup_workspace(platform::Workspace{.root = root});
            static_cast<void>(MoveFileExW(
                helper.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT));
        }
    } cleanup{.root = root, .helper = *helper};
    const DWORD parent_wait = WaitForSingleObject(parent, INFINITE);
    if (parent_wait != WAIT_OBJECT_0) {
        return report_failure("could not wait for the running Kasumi process");
    }
    std::string manager;
    if (package_managed_installation(target, manager)) {
        return report_failure(
            i18n::format(i18n::Key::UpdateManagedInstallation, manager));
    }
    auto digest = refetch_official_digest(
        archive, version, *package, platform::Workspace{.root = root});
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
    platform::cleanup_workspace(
        platform::Workspace{.root = prepared->path.parent_path()});
    const InstallAction elevate = [&]() -> InstallResult {
        std::println("{}", i18n::tr(i18n::Key::UpdateAdminRequired));
        std::println("{}", i18n::tr(i18n::Key::UpdateRequestPermission));
        auto elevated = launch_elevated_windows(*helper,
                                                archive,
                                                version,
                                                language_code(),
                                                parent_id,
                                                *expected_identity);
        if (!elevated) {
            return std::unexpected(
                InstallFailure{.kind = InstallFailure::Kind::Other,
                               .detail = elevated.error()});
        }
        return {};
    };
    auto result = install_once_then_elevate(
        [&]() -> InstallResult {
            return std::move(installed);
        },
        elevate);
    if (!result) {
        return report_failure(result.error().detail);
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
    if (!path.is_absolute() || path.lexically_normal() != path) {
        return std::unexpected(
            "system tool path is not an absolute normalized path");
    }
    struct stat status{};
    auto current = path.root_path();
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
        if (S_ISLNK(status.st_mode)) {
            if (status.st_uid != 0) {
                return std::unexpected(
                    "system tool path contains a non-root symlink");
            }
        } else {
            const bool final_component =
                std::next(iterator) == components.end();
            if (!trusted_root_stat(status, !final_component)) {
                return std::unexpected(
                    "system tool path contains an untrusted or writable entry");
            }
        }
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
    const auto checksum_url =
        "https://github.com/" + std::string{GITHUB_REPOSITORY} +
        "/releases/download/" + std::string{tag} + "/" + package->checksum;
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
    if (!uid || !package || !target ||
        target->filename() != platform::path::from_utf8("kasumi")) {
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
    std::error_code error;
    const auto archive_size = std::filesystem::file_size(archive, error);
    if (!stage_valid ||
        archive.filename() != platform::path::from_utf8(package->archive) ||
        !is_regular_file_without_redirect(archive) || error ||
        archive_size == 0 || archive_size > PACKAGE_LIMIT) {
        return report_failure(
            "update package is outside the original private staging directory");
    }
    std::string manager;
    if (package_managed_installation(*target, manager)) {
        return report_failure(
            i18n::format(i18n::Key::UpdateManagedInstallation, manager));
    }
    auto workspace = platform::create_workspace("update-elevated");
    if (!workspace) {
        return report_failure(workspace.error());
    }
    struct Cleanup {
        platform::Workspace value;
        ~Cleanup() {
            platform::cleanup_workspace(value);
        }
    } cleanup{.value = *workspace};
    const auto trusted_archive =
        platform::workspace_file(*workspace, package->archive);
    if (trusted_archive.empty() ||
        !std::filesystem::copy_file(archive,
                                    trusted_archive,
                                    std::filesystem::copy_options::none,
                                    error) ||
        error) {
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
    hooks.install = [](const PreparedExecutable& prepared,
                       const std::filesystem::path& destination) {
        return install_prepared_executable(
            prepared.path, destination, prepared.sha256);
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
    if (executable->filename() != platform::path::from_utf8("kasumi.exe")) {
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
#else
    if (executable->filename() != platform::path::from_utf8("kasumi")) {
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
    struct Cleanup {
        platform::Workspace value;
        bool released = false;
        ~Cleanup() {
            if (!released) {
                platform::cleanup_workspace(value);
            }
        }
    } cleanup{.value = *workspace};
    const ApiGet get =
        [&](std::string_view url,
            std::size_t limit) -> std::expected<HttpResponse, std::string> {
        auto body = get_text(std::string{url}, limit, *workspace);
        if (!body) {
            return std::unexpected(body.error());
        }
        return HttpResponse{.status = 200, .body = std::move(*body)};
    };
    auto releases = fetch_releases(get);
    if (!releases) {
        return report_failure(releases.error());
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
std::expected<void, std::string>
grant_windows_admin_read_access(const std::filesystem::path& root) {
    PACL dacl = nullptr;
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    auto writable = root.wstring();
    const auto query = GetNamedSecurityInfoW(writable.data(),
                                             SE_FILE_OBJECT,
                                             DACL_SECURITY_INFORMATION |
                                                 OWNER_SECURITY_INFORMATION,
                                             &owner,
                                             nullptr,
                                             &dacl,
                                             nullptr,
                                             &descriptor);
    if (query != ERROR_SUCCESS || descriptor == nullptr || dacl == nullptr) {
        if (descriptor != nullptr) {
            LocalFree(descriptor);
        }
        return std::unexpected(
            "could not inspect update workspace permissions");
    }
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    const bool control_valid =
        GetSecurityDescriptorControl(descriptor, &control, &revision) != 0 &&
        (control & SE_DACL_PROTECTED) != 0;
    const bool owner_valid = owner != nullptr;
    bool valid = control_valid && owner_valid;
    alignas(DWORD) std::array<std::byte, SECURITY_MAX_SID_SIZE> system_sid{};
    DWORD system_size = static_cast<DWORD>(system_sid.size());
    alignas(DWORD) std::array<std::byte, SECURITY_MAX_SID_SIZE> admin_sid{};
    DWORD admin_size = static_cast<DWORD>(admin_sid.size());
    valid =
        valid &&
        CreateWellKnownSid(
            WinLocalSystemSid, nullptr, system_sid.data(), &system_size) != 0 &&
        CreateWellKnownSid(WinBuiltinAdministratorsSid,
                           nullptr,
                           admin_sid.data(),
                           &admin_size) != 0;
    HANDLE token = nullptr;
    valid = valid &&
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != 0;
    std::vector<std::byte> token_data;
    if (valid) {
        DWORD required = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &required);
        token_data.resize(required);
        valid =
            required != 0 &&
            GetTokenInformation(
                token, TokenUser, token_data.data(), required, &required) != 0;
    }
    if (token != nullptr) {
        CloseHandle(token);
    }
    const auto* current_user =
        valid ? reinterpret_cast<const TOKEN_USER*>(token_data.data())
              : nullptr;
    ACL_SIZE_INFORMATION info{};
    const bool acl_readable =
        GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation) != 0;
    valid = valid && acl_readable && info.AceCount == 2;
    bool has_workspace_user = false;
    bool has_system = false;
    PSID workspace_user = nullptr;
    for (DWORD index = 0; valid && index < info.AceCount; ++index) {
        void* raw = nullptr;
        if (!GetAce(dacl, index, &raw) || raw == nullptr) {
            valid = false;
            break;
        }
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        auto* sid = reinterpret_cast<PSID>(&ace->SidStart);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            ace->Mask != FILE_ALL_ACCESS) {
            valid = false;
        } else if (EqualSid(sid, system_sid.data())) {
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
        owner != nullptr &&
        ((workspace_user != nullptr && EqualSid(owner, workspace_user)) ||
         EqualSid(owner, admin_sid.data()));
    if (!valid || !has_workspace_user || !has_system || !owner_is_expected) {
        LocalFree(descriptor);
        return std::unexpected(
            "update workspace ACL is not the expected private ACL");
    }
    EXPLICIT_ACCESSW access{};
    access.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(admin_sid.data());
    PACL updated_acl = nullptr;
    const auto merge = SetEntriesInAclW(1, &access, dacl, &updated_acl);
    LocalFree(descriptor);
    if (merge != ERROR_SUCCESS || updated_acl == nullptr) {
        if (updated_acl != nullptr) {
            LocalFree(updated_acl);
        }
        return std::unexpected("could not grant read-only administrator access "
                               "to update workspace");
    }
    const auto set = SetNamedSecurityInfoW(
        writable.data(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        updated_acl,
        nullptr);
    LocalFree(updated_acl);
    if (set != ERROR_SUCCESS) {
        return std::unexpected(
            "could not secure update workspace for UAC handoff");
    }
    return validate_windows_workspace_acl(root);
}

std::expected<void, std::string>
validate_windows_workspace_acl(const std::filesystem::path& root) {
    return validate_windows_workspace_acl_impl(root);
}

std::optional<WindowsFileIdentity>
windows_file_identity(const std::filesystem::path& path) {
    HANDLE file =
        CreateFileW(path.c_str(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    FILE_ID_INFO info{};
    const bool valid =
        GetFileInformationByHandleEx(
            file, FileAttributeTagInfo, &attributes, sizeof(attributes)) != 0 &&
        (attributes.FileAttributes &
         (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) == 0 &&
        GetFileInformationByHandleEx(file, FileIdInfo, &info, sizeof(info)) !=
            0;
    CloseHandle(file);
    if (!valid) {
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
    if (mode.starts_with("--kasumi-update-")) {
        int wide_argc = 0;
        LPWSTR* wide_argv = CommandLineToArgvW(GetCommandLineW(), &wide_argc);
        if (wide_argv == nullptr || wide_argc <= 0) {
            return report_failure(
                "could not decode Unicode installer arguments");
        }
        std::vector<std::string> utf8_arguments;
        utf8_arguments.reserve(static_cast<std::size_t>(wide_argc));
        for (int index = 0; index < wide_argc; ++index) {
            auto utf8 = narrow_utf8(wide_argv[index]);
            if (!utf8) {
                LocalFree(wide_argv);
                return report_failure(
                    "installer argument is not valid Unicode");
            }
            utf8_arguments.push_back(std::move(*utf8));
        }
        LocalFree(wide_argv);
        std::vector<char*> utf8_argv;
        utf8_argv.reserve(utf8_arguments.size());
        for (auto& argument : utf8_arguments) {
            utf8_argv.push_back(argument.data());
        }
        if (utf8_arguments.size() < 2) {
            return report_failure("invalid installer invocation");
        }
        const std::string_view internal_mode{utf8_arguments[1]};
        if (internal_mode == "--kasumi-update-helper") {
            return run_windows_wait_helper(static_cast<int>(utf8_argv.size()),
                                           utf8_argv.data());
        }
        if (internal_mode == "--kasumi-update-elevated") {
            return run_windows_elevated_helper(
                static_cast<int>(utf8_argv.size()), utf8_argv.data());
        }
        return report_failure("unknown internal update mode");
    }
#else
    if (mode == "--kasumi-update-install") {
        return run_linux_install_helper(argc, argv);
    }
#endif
    return report_failure("unknown internal update mode");
}

} // namespace kasumi::cli::update
