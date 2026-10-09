#ifndef KASUMI_CLI_UPDATE_HPP
#define KASUMI_CLI_UPDATE_HPP

#include <array>
#include <compare>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::cli::update {

struct Version {
    unsigned long long major = 0;
    unsigned long long minor = 0;
    unsigned long long patch = 0;
    std::vector<std::string> prerelease;
    std::string text;
};

struct Asset {
    std::string name;
    std::string url;
};

struct Release {
    std::string tag;
    bool draft = false;
    bool prerelease = false;
    std::vector<Asset> assets;
};

struct PackageNames {
    std::string archive;
    std::string checksum;
    std::string executable;
};

struct PreparedExecutable {
    std::filesystem::path path;
    std::string sha256;
};

struct HttpResponse {
    int status = 0;
    std::string body;
};

struct InstallFailure {
    enum class Kind {
        Other,
        PermissionDenied
    };

    Kind kind = Kind::Other;
    std::string detail;
};

using InstallResult = std::expected<void, InstallFailure>;
using InstallAction = std::function<InstallResult()>;

struct InstallHooks {
    std::function<std::expected<std::string, std::string>(
        const std::filesystem::path&)>
        hash_file;
    std::function<std::expected<void, std::string>(
        const std::filesystem::path&, const std::filesystem::path&)>
        replace_atomically;
    std::function<std::expected<void, std::string>(
        const std::filesystem::path&)>
        validate_target;
};

using ApiGet = std::function<std::expected<HttpResponse, std::string>(
    std::string_view url, std::size_t maximum_bytes)>;

std::optional<Version> parse_version(std::string_view text);
std::strong_ordering compare_versions(const Version& left,
                                      const Version& right) noexcept;
std::optional<std::size_t>
select_release_index(std::span<const Release> releases);
bool installed_version_is_current_or_newer(std::string_view current,
                                           const Version& latest);
std::expected<std::vector<Release>, std::string>
parse_releases_json(std::string_view body);
std::expected<std::vector<Release>, std::string>
fetch_releases(const ApiGet& get);
std::optional<PackageNames> package_names_for_this_platform();
std::optional<std::string> parse_checksum(std::string_view body,
                                          std::string_view expected_name);
bool valid_archive_listing(std::string_view listing,
                           const PackageNames& package);
bool valid_verbose_archive_listing(std::string_view listing,
                                   const PackageNames& package);
bool official_asset_url(std::string_view tag,
                        std::string_view name,
                        std::string_view url);
std::optional<std::filesystem::path> current_executable_path();
std::expected<std::string, std::string>
sha256_file(const std::filesystem::path& path);
std::expected<std::string, std::string>
verify_package_checksum(const std::filesystem::path& archive,
                        const std::filesystem::path& checksum_file,
                        std::string_view archive_name);
InstallResult install_prepared_executable(const std::filesystem::path& prepared,
                                          const std::filesystem::path& target,
                                          std::string_view expected_sha256,
                                          const InstallHooks* hooks = nullptr);
InstallResult install_once_then_elevate(const InstallAction& install,
                                        const InstallAction& elevate);

#if defined(__linux__)
std::expected<std::filesystem::path, std::string>
resolve_linux_system_tool(std::string_view name);
std::expected<void, std::string>
validate_linux_system_tool(const std::filesystem::path& path);

enum class LinuxElevationState {
    Succeeded,
    AuthenticationUnavailable,
    Cancelled,
    Failed
};

struct LinuxElevationResult {
    LinuxElevationState state = LinuxElevationState::Failed;
    std::string detail;
};

using LinuxElevationAttempt = std::function<LinuxElevationResult()>;

LinuxElevationResult
classify_linux_pkexec_result(int exit_code, std::string_view error_output);
LinuxElevationResult
attempt_linux_elevation(bool interactive,
                        const LinuxElevationAttempt& pkexec,
                        const LinuxElevationAttempt& sudo);

struct LinuxHandoffHooks {
    std::function<std::expected<std::string, std::string>(std::string_view)>
        fetch_checksum;
    std::function<std::expected<PreparedExecutable, std::string>(
        const std::filesystem::path&, std::string_view)>
        prepare;
    std::function<InstallResult(const PreparedExecutable&,
                                const std::filesystem::path&)>
        install;
};

InstallResult install_linux_handoff(const std::filesystem::path& archive,
                                    std::string_view tag,
                                    const std::filesystem::path& target,
                                    const LinuxHandoffHooks& hooks);
#endif

#if defined(_WIN32)
struct WindowsFileIdentity {
    std::uint64_t volume_serial = 0;
    std::array<std::uint8_t, 16> file_id{};
    friend bool operator==(const WindowsFileIdentity&,
                           const WindowsFileIdentity&) = default;
};

std::expected<void, std::string>
grant_windows_admin_read_access(const std::filesystem::path& root);
std::expected<void, std::string>
validate_windows_workspace_acl(const std::filesystem::path& root);
std::optional<WindowsFileIdentity>
windows_file_identity(const std::filesystem::path& path);
bool windows_file_identity_matches(const std::filesystem::path& path,
                                   const WindowsFileIdentity& expected);
std::wstring windows_join_arguments(const std::vector<std::wstring>& arguments);
std::optional<std::vector<std::wstring>>
windows_decode_arguments(std::wstring_view command_line);
#endif

// Runs only the public `kasumi update` operation or its private installer
// handoff.
int run(int argc, char* argv[]);

} // namespace kasumi::cli::update

#endif
