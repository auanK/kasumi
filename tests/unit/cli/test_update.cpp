#include "cli/parser.hpp"
#include "cli/update.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/durability.hpp"
#include "platform/workspace.hpp"

#include <array>
#include <compare>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

TEST(CliUpdateTest, ParsesTheSinglePublicUpdateCommand) {
    std::vector<std::string> values{"kasumi", "update"};
    std::vector<char*> argv;
    for (auto& value : values) {
        argv.push_back(value.data());
    }

    const auto result =
        kasumi::cli::parse(static_cast<int>(argv.size()), argv.data());
    ASSERT_TRUE(result.has_value()) << "kasumi update is not available yet";
    EXPECT_TRUE(std::holds_alternative<kasumi::cli::UpdateInvocation>(*result));

    values.push_back("extra");
    argv.clear();
    for (auto& value : values) {
        argv.push_back(value.data());
    }
    EXPECT_FALSE(kasumi::cli::parse(static_cast<int>(argv.size()), argv.data())
                     .has_value());
}

TEST(CliUpdateTest, ComparesNumericAndPrereleaseVersionsBySemverOrder) {
    const auto ten = kasumi::cli::update::parse_version("v0.10.0");
    const auto nine = kasumi::cli::update::parse_version("v0.9.99");
    const auto alpha = kasumi::cli::update::parse_version("v0.10.0-alpha.2");
    const auto beta = kasumi::cli::update::parse_version("v0.10.0-beta");
    ASSERT_TRUE(ten && nine && alpha && beta);
    EXPECT_EQ(kasumi::cli::update::compare_versions(*ten, *nine),
              std::strong_ordering::greater);
    EXPECT_EQ(kasumi::cli::update::compare_versions(*alpha, *beta),
              std::strong_ordering::less);
    EXPECT_EQ(kasumi::cli::update::compare_versions(*alpha, *ten),
              std::strong_ordering::less);
    EXPECT_FALSE(kasumi::cli::update::parse_version("v01.2.3"));
    EXPECT_FALSE(kasumi::cli::update::parse_version("v1.2"));
    EXPECT_TRUE(kasumi::cli::update::parse_version("v1.2.3-alpha01"));
    EXPECT_FALSE(kasumi::cli::update::parse_version("v1.2.3-01"));
    const auto build_one = kasumi::cli::update::parse_version("v1.2.3+build.1");
    const auto build_two = kasumi::cli::update::parse_version("v1.2.3+build.2");
    ASSERT_TRUE(build_one && build_two);
    EXPECT_EQ(kasumi::cli::update::compare_versions(*build_one, *build_two),
              std::strong_ordering::equal);
}

TEST(CliUpdateTest, SelectsUnstableChannelUntilStableOnePointOhExists) {
    using kasumi::cli::update::Asset;
    using kasumi::cli::update::Release;
    const std::vector<Release> unstable{
        {"v0.10.0-alpha.2", false, true, {}},
        {"v0.9.9", false, false, {}},
        {"v1.0.0-beta", false, true, {}},
        {"v9.0.0", true, false, {}},
        {"not-a-version", false, false, {}},
    };
    const auto selected = kasumi::cli::update::select_release_index(unstable);
    ASSERT_TRUE(selected);
    EXPECT_EQ(unstable[*selected].tag, "v0.10.0-alpha.2");

    const std::vector<Release> stable{
        {"v0.99.0", false, false, {}},
        {"v1.0.0-beta", false, true, {}},
        {"v1.0.0", false, false, {}},
        {"v1.10.0", false, false, {}},
        {"v2.0.0-rc.1", false, true, {}},
    };
    const auto stable_selected =
        kasumi::cli::update::select_release_index(stable);
    ASSERT_TRUE(stable_selected);
    EXPECT_EQ(stable[*stable_selected].tag, "v1.10.0");
    EXPECT_TRUE(kasumi::cli::update::installed_version_is_current_or_newer(
        "3.0.0", *kasumi::cli::update::parse_version("v1.10.0")));
}

TEST(CliUpdateTest, ParsesOnlyTheExpectedSha256AndArchiveEntries) {
    using kasumi::cli::update::PackageNames;
    const PackageNames package{"kasumi-linux-x86_64.tar.gz",
                               "kasumi-linux-x86_64.tar.gz.sha256",
                               "kasumi"};
    const std::string digest(64, 'a');
    EXPECT_EQ(kasumi::cli::update::parse_checksum(
                  digest + "  " + package.archive + "\n", package.archive),
              digest);
    EXPECT_FALSE(kasumi::cli::update::parse_checksum(
        digest + "  other.tar.gz\n", package.archive));
    EXPECT_FALSE(kasumi::cli::update::parse_checksum(
        std::string(63, 'a') + "  " + package.archive, package.archive));
    EXPECT_TRUE(kasumi::cli::update::valid_archive_listing(
        "kasumi\nLICENSE\nTHIRD_PARTY_NOTICES.md\n", package));
    EXPECT_FALSE(kasumi::cli::update::valid_archive_listing(
        "../kasumi\nLICENSE\nTHIRD_PARTY_NOTICES.md\n", package));
    EXPECT_FALSE(kasumi::cli::update::valid_archive_listing(
        "kasumi\nkasumi\nLICENSE\nTHIRD_PARTY_NOTICES.md\n", package));
    EXPECT_FALSE(kasumi::cli::update::valid_archive_listing(
        "kasumi\nLICENSE\nTHIRD_PARTY_NOTICES.md\nextra\n", package));
    EXPECT_TRUE(kasumi::cli::update::valid_archive_listing(
        "CHANGELOG.md\nkasumi\nLICENSE\nREADME.md\n"
        "THIRD_PARTY_NOTICES.md\n",
        package));
    EXPECT_FALSE(kasumi::cli::update::valid_archive_listing(
        "CHANGELOG.md\nkasumi\nLICENSE\nREADME.md\n"
        "THIRD_PARTY_NOTICES.md\nextra\n",
        package));
    const std::string verbose =
        "-rwxr-xr-x user/group 1024 2026-10-09 12:00 kasumi\n"
        "-rw-r--r-- user/group 128 2026-10-09 12:00 LICENSE\n"
        "-rw-r--r-- user/group 256 2026-10-09 12:00 THIRD_PARTY_NOTICES.md\n";
    EXPECT_TRUE(
        kasumi::cli::update::valid_verbose_archive_listing(verbose, package));
    const std::string official_verbose =
        "-rw-rw-r-- 0 0 0 6468 set 19 22:23 CHANGELOG.md\n"
        "-rwxrwxr-x 0 0 0 4229632 set 19 22:30 kasumi.exe\n"
        "-rw-rw-r-- 0 0 0 1083 set 19 22:23 LICENSE\n"
        "-rw-rw-r-- 0 0 0 1944 set 19 22:23 README.md\n"
        "-rw-rw-r-- 0 0 0 11264 set 19 22:23 THIRD_PARTY_NOTICES.md\n";
    const PackageNames windows_package{"kasumi-windows-x86_64.zip",
                                       "kasumi-windows-x86_64.zip.sha256",
                                       "kasumi.exe"};
    EXPECT_TRUE(kasumi::cli::update::valid_verbose_archive_listing(
        official_verbose, windows_package));
    EXPECT_FALSE(kasumi::cli::update::valid_verbose_archive_listing(
        official_verbose + "-rw-rw-r-- 0 0 20 set 19 22:23 unexpected.txt\n",
        windows_package));
    EXPECT_FALSE(kasumi::cli::update::valid_verbose_archive_listing(
        "lrwxrwxrwx user/group 0 2026-10-09 12:00 kasumi\n"
        "-rw-r--r-- user/group 128 2026-10-09 12:00 LICENSE\n"
        "-rw-r--r-- user/group 256 2026-10-09 12:00 THIRD_PARTY_NOTICES.md\n",
        package));
    EXPECT_FALSE(kasumi::cli::update::valid_verbose_archive_listing(
        "-rwxr-xr-x user/group 1024 2026-10-09 12:00 ../kasumi\n"
        "-rw-r--r-- user/group 128 2026-10-09 12:00 LICENSE\n"
        "-rw-r--r-- user/group 256 2026-10-09 12:00 THIRD_PARTY_NOTICES.md\n",
        package));
    EXPECT_FALSE(kasumi::cli::update::valid_verbose_archive_listing(
        "-rwxr-xr-x user/group 999999999 2026-10-09 12:00 kasumi\n"
        "-rw-r--r-- user/group 128 2026-10-09 12:00 LICENSE\n"
        "-rw-r--r-- user/group 256 2026-10-09 12:00 THIRD_PARTY_NOTICES.md\n",
        package));
}

TEST(CliUpdateTest, RejectsForeignAssetUrlsAndParsesGitHubReleaseResponses) {
    EXPECT_TRUE(kasumi::cli::update::official_asset_url(
        "v0.7.0",
        "kasumi-windows-x86_64.zip",
        "https://github.com/auanK/kasumi/releases/download/v0.7.0/"
        "kasumi-windows-x86_64.zip"));
    EXPECT_FALSE(kasumi::cli::update::official_asset_url(
        "v0.7.0",
        "kasumi-windows-x86_64.zip",
        "https://evil.example/kasumi-windows-x86_64.zip"));
    const auto parsed = kasumi::cli::update::parse_releases_json(R"json([
      {"tag_name":"v0.7.0","draft":false,"prerelease":true,
       "assets":[{"name":"kasumi-linux-x86_64.tar.gz",
        "browser_download_url":"https://github.com/auanK/kasumi/releases/download/v0.7.0/kasumi-linux-x86_64.tar.gz"}]}
    ])json");
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 1);
    EXPECT_EQ((*parsed)[0].tag, "v0.7.0");
    EXPECT_EQ((*parsed)[0].assets.size(), 1);
}

TEST(CliUpdateTest, ReleaseListingFailsClosedOnHttpAndMalformedResponses) {
    using namespace kasumi::cli::update;
    auto failed_http = fetch_releases(
        [](std::string_view,
           std::size_t) -> std::expected<HttpResponse, std::string> {
            return HttpResponse{.status = 503};
        });
    EXPECT_FALSE(failed_http);
    auto failed_network = fetch_releases(
        [](std::string_view,
           std::size_t) -> std::expected<HttpResponse, std::string> {
            return std::unexpected("injected network failure");
        });
    EXPECT_FALSE(failed_network);
    EXPECT_FALSE(parse_releases_json("{broken"));
    auto timeout = fetch_releases(
        [](std::string_view,
           std::size_t) -> std::expected<HttpResponse, std::string> {
            return std::unexpected("request timed out");
        });
    EXPECT_FALSE(timeout);
}

TEST(CliUpdateTest, ReleaseListingReadsAllPages) {
    using namespace kasumi::cli::update;
    std::vector<std::string> urls;
    const auto result = fetch_releases([&](std::string_view url, std::size_t)
                                           -> std::expected<HttpResponse,
                                                            std::string> {
        urls.emplace_back(url);
        if (url.ends_with("page=1")) {
            std::string body = "[";
            for (int index = 0; index < 100; ++index) {
                if (index != 0) {
                    body += ',';
                }
                body +=
                    R"({"tag_name":"invalid","draft":false,"prerelease":false,"assets":[]})";
            }
            body += ']';
            return HttpResponse{.status = 200, .body = std::move(body)};
        }
        return HttpResponse{.status = 200, .body = "[]"};
    });
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 100);
    ASSERT_EQ(urls.size(), 2);
    EXPECT_TRUE(urls[0].ends_with("page=1"));
    EXPECT_TRUE(urls[1].ends_with("page=2"));
}

TEST(CliUpdateTest, IdentifiesRunningExecutableAndPlatformPackage) {
    const auto executable = kasumi::cli::update::current_executable_path();
    ASSERT_TRUE(executable);
    EXPECT_TRUE(executable->is_absolute());
    EXPECT_TRUE(std::filesystem::is_regular_file(*executable));
    const auto package = kasumi::cli::update::package_names_for_this_platform();
    ASSERT_TRUE(package);
#if defined(_WIN32)
    EXPECT_EQ(package->archive, "kasumi-windows-x86_64.zip");
    EXPECT_EQ(package->executable, "kasumi.exe");
#else
    EXPECT_EQ(package->archive, "kasumi-linux-x86_64.tar.gz");
    EXPECT_EQ(package->executable, "kasumi");
#endif
}

TEST(CliUpdateTest, VerifiesChecksumAndRejectsMismatchInTemporaryFiles) {
    auto workspace = kasumi::test::make_temp_workspace("update-checksum");
    const auto archive = kasumi::test::workspace_path(workspace, "package.bin");
    const auto checksum =
        kasumi::test::workspace_path(workspace, "package.sha256");
    constexpr std::string_view digest =
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    {
        std::ofstream output(archive, std::ios::binary);
        output << "test";
    }
    {
        std::ofstream output(checksum, std::ios::binary);
        output << digest << "  kasumi-linux-x86_64.tar.gz\n";
    }
    const auto verified = kasumi::cli::update::verify_package_checksum(
        archive, checksum, "kasumi-linux-x86_64.tar.gz");
    ASSERT_TRUE(verified.has_value()) << verified.error();
    EXPECT_EQ(*verified, digest);

    {
        std::ofstream output(checksum, std::ios::binary | std::ios::trunc);
        output << std::string(64, 'a') << "  kasumi-linux-x86_64.tar.gz\n";
    }
    EXPECT_FALSE(kasumi::cli::update::verify_package_checksum(
        archive, checksum, "kasumi-linux-x86_64.tar.gz"));
}

TEST(CliUpdateTest, InstallsOnlyIntoTemporaryTargetAndKeepsRecoveryCopy) {
    auto workspace = kasumi::test::make_temp_workspace("update-install");
    const auto target = kasumi::test::workspace_path(workspace, "kasumi");
    const auto prepared = kasumi::test::workspace_path(workspace, "prepared");
    const auto unrelated =
        kasumi::test::workspace_path(workspace, "profile.bin");
    {
        std::ofstream output(target, std::ios::binary);
        output << "old executable";
    }
    {
        std::ofstream output(prepared, std::ios::binary);
        output << "new executable";
    }
    {
        std::ofstream output(unrelated, std::ios::binary);
        output << "profile data";
    }

    const auto expected = kasumi::cli::update::sha256_file(prepared);
    ASSERT_TRUE(expected.has_value());
    const auto installed = kasumi::cli::update::install_prepared_executable(
        prepared, target, *expected);
    ASSERT_TRUE(installed.has_value()) << installed.error().detail;
    std::ifstream target_input(target, std::ios::binary);
    const std::string target_body{std::istreambuf_iterator<char>{target_input},
                                  std::istreambuf_iterator<char>{}};
    EXPECT_EQ(target_body, "new executable");
    std::ifstream unrelated_input(unrelated, std::ios::binary);
    const std::string unrelated_body{
        std::istreambuf_iterator<char>{unrelated_input},
        std::istreambuf_iterator<char>{}};
    EXPECT_EQ(unrelated_body, "profile data");

    bool found_recovery_copy = false;
    for (const auto& entry : std::filesystem::directory_iterator(
             kasumi::test::workspace_root(workspace))) {
        if (entry.path().filename().string().starts_with(".kasumi-previous-")) {
            std::ifstream backup(entry.path(), std::ios::binary);
            const std::string backup_body{
                std::istreambuf_iterator<char>{backup},
                std::istreambuf_iterator<char>{}};
            EXPECT_EQ(backup_body, "old executable");
            found_recovery_copy = true;
        }
    }
    EXPECT_TRUE(found_recovery_copy);
}

TEST(CliUpdateTest, RejectsPreparedExecutableChangedAfterVerification) {
    auto workspace = kasumi::test::make_temp_workspace("update-tamper");
    const auto target = kasumi::test::workspace_path(workspace, "kasumi");
    const auto prepared = kasumi::test::workspace_path(workspace, "prepared");
    {
        std::ofstream output(target, std::ios::binary);
        output << "original executable";
    }
    {
        std::ofstream output(prepared, std::ios::binary);
        output << "verified executable";
    }
    const auto expected = kasumi::cli::update::sha256_file(prepared);
    ASSERT_TRUE(expected.has_value());
    {
        std::ofstream output(prepared, std::ios::binary | std::ios::trunc);
        output << "tampered executable";
    }

    const auto installed = kasumi::cli::update::install_prepared_executable(
        prepared, target, *expected);

    ASSERT_FALSE(installed.has_value());
    std::ifstream input(target, std::ios::binary);
    const std::string body{std::istreambuf_iterator<char>{input},
                           std::istreambuf_iterator<char>{}};
    EXPECT_EQ(body, "original executable");
}

TEST(CliUpdateTest, ElevatesOnlyAfterAnActualPermissionFailureAndOnlyOnce) {
    using namespace kasumi::cli::update;
    int direct_calls = 0;
    int elevated_calls = 0;
    const auto result = install_once_then_elevate(
        [&]() -> InstallResult {
            ++direct_calls;
            return std::unexpected(
                InstallFailure{.kind = InstallFailure::Kind::Other,
                               .detail = "archive verification failed"});
        },
        [&]() -> InstallResult {
            ++elevated_calls;
            return {};
        });
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, InstallFailure::Kind::Other);
    EXPECT_EQ(direct_calls, 1);
    EXPECT_EQ(elevated_calls, 0);
}

TEST(CliUpdateTest, ElevationIsAttemptedOnceForPermissionFailure) {
    using namespace kasumi::cli::update;
    int direct_calls = 0;
    int elevated_calls = 0;
    const auto result = install_once_then_elevate(
        [&]() -> InstallResult {
            ++direct_calls;
            return std::unexpected(
                InstallFailure{.kind = InstallFailure::Kind::PermissionDenied,
                               .detail = "replace denied"});
        },
        [&]() -> InstallResult {
            ++elevated_calls;
            return {};
        });
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(direct_calls, 1);
    EXPECT_EQ(elevated_calls, 1);
}

TEST(CliUpdateTest, ReplacementPermissionFailureCanOccurInWritableDirectory) {
    using namespace kasumi::cli::update;
    auto workspace = kasumi::test::make_temp_workspace("update-denied-replace");
    const auto target = kasumi::test::workspace_path(workspace, "kasumi");
    const auto prepared = kasumi::test::workspace_path(workspace, "prepared");
    {
        std::ofstream output(target, std::ios::binary);
        output << "original executable";
    }
    {
        std::ofstream output(prepared, std::ios::binary);
        output << "verified executable";
    }
    const auto digest = sha256_file(prepared);
    ASSERT_TRUE(digest);
    InstallHooks hooks;
    const std::string permission_code =
#if defined(_WIN32)
        "5";
#else
        "13";
#endif
    hooks.replace_atomically =
        [&](const auto&, const auto&) -> std::expected<void, std::string> {
        return std::unexpected("replace_atomically failed (native_code=" +
                               permission_code + "): permission denied");
    };
    int elevation_calls = 0;
    const auto result = install_once_then_elevate(
        [&]() -> InstallResult {
            return install_prepared_executable(
                prepared, target, *digest, &hooks);
        },
        [&]() -> InstallResult {
            ++elevation_calls;
            return {};
        });

    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(elevation_calls, 1);
    std::ifstream input(target, std::ios::binary);
    const std::string body{std::istreambuf_iterator<char>{input},
                           std::istreambuf_iterator<char>{}};
    EXPECT_EQ(body, "original executable");
}

TEST(CliUpdateTest, ElevationCancellationOrFailureIsNotRetried) {
    using namespace kasumi::cli::update;
    int direct_calls = 0;
    int elevated_calls = 0;
    const auto result = install_once_then_elevate(
        [&]() -> InstallResult {
            ++direct_calls;
            return std::unexpected(
                InstallFailure{.kind = InstallFailure::Kind::PermissionDenied,
                               .detail = "replace denied"});
        },
        [&]() -> InstallResult {
            ++elevated_calls;
            return std::unexpected(
                InstallFailure{.kind = InstallFailure::Kind::Other,
                               .detail = "authorization cancelled"});
        });
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().detail, "authorization cancelled");
    EXPECT_EQ(direct_calls, 1);
    EXPECT_EQ(elevated_calls, 1);
}

TEST(CliUpdateTest, CancelledElevationPreservesTheInstalledExecutable) {
    using namespace kasumi::cli::update;
    auto workspace =
        kasumi::test::make_temp_workspace("update-cancelled-elevation");
    const auto target = kasumi::test::workspace_path(workspace, "kasumi");
    {
        std::ofstream output(target, std::ios::binary);
        output << "original executable";
    }
    const auto result = install_once_then_elevate(
        []() -> InstallResult {
            return std::unexpected(
                InstallFailure{.kind = InstallFailure::Kind::PermissionDenied,
                               .detail = "replace denied"});
        },
        []() -> InstallResult {
            return std::unexpected(
                InstallFailure{.kind = InstallFailure::Kind::Other,
                               .detail = "authorization cancelled"});
        });
    ASSERT_FALSE(result);
    std::ifstream input(target, std::ios::binary);
    const std::string body{std::istreambuf_iterator<char>{input},
                           std::istreambuf_iterator<char>{}};
    EXPECT_EQ(body, "original executable");
}

TEST(CliUpdateTest, FailedAtomicReplacementLeavesOriginalAndIsNotElevated) {
    using namespace kasumi::cli::update;
    auto workspace = kasumi::test::make_temp_workspace("update-interrupted");
    const auto target = kasumi::test::workspace_path(workspace, "kasumi");
    const auto prepared = kasumi::test::workspace_path(workspace, "prepared");
    {
        std::ofstream output(target, std::ios::binary);
        output << "original executable";
    }
    {
        std::ofstream output(prepared, std::ios::binary);
        output << "new executable";
    }
    const auto digest = sha256_file(prepared);
    ASSERT_TRUE(digest);
    InstallHooks hooks;
    hooks.replace_atomically =
        [](const auto&, const auto&) -> std::expected<void, std::string> {
        return std::unexpected("injected non-permission replacement failure");
    };
    int elevated_calls = 0;
    const auto result = install_once_then_elevate(
        [&]() -> InstallResult {
            return install_prepared_executable(
                prepared, target, *digest, &hooks);
        },
        [&]() -> InstallResult {
            ++elevated_calls;
            return {};
        });

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(elevated_calls, 0);
    std::ifstream input(target, std::ios::binary);
    const std::string body{std::istreambuf_iterator<char>{input},
                           std::istreambuf_iterator<char>{}};
    EXPECT_EQ(body, "original executable");
}

TEST(CliUpdateTest,
     FailedPostInstallVerificationKeepsRecoveryCopyOnRollbackFailure) {
    using namespace kasumi::cli::update;
    auto workspace =
        kasumi::test::make_temp_workspace("update-rollback-failure");
    const auto target = kasumi::test::workspace_path(workspace, "kasumi");
    const auto prepared = kasumi::test::workspace_path(workspace, "prepared");
    {
        std::ofstream output(target, std::ios::binary);
        output << "old executable";
    }
    {
        std::ofstream output(prepared, std::ios::binary);
        output << "new executable";
    }
    const auto digest = sha256_file(prepared);
    ASSERT_TRUE(digest);
    InstallHooks hooks;
    int target_hash_calls = 0;
    hooks.hash_file = [&](const std::filesystem::path& path)
        -> std::expected<std::string, std::string> {
        if (path == target) {
            ++target_hash_calls;
            if (target_hash_calls == 2) {
                return std::string(64, '0');
            }
        }
        return sha256_file(path);
    };
    int replace_calls = 0;
    hooks.replace_atomically =
        [&](const auto& source,
            const auto& destination) -> std::expected<void, std::string> {
        ++replace_calls;
        if (replace_calls == 2) {
            return std::unexpected("injected rollback failure");
        }
        return kasumi::platform::durability::replace_atomically(source,
                                                                destination);
    };

    const auto result =
        install_prepared_executable(prepared, target, *digest, &hooks);

    ASSERT_FALSE(result.has_value());
    EXPECT_NE(result.error().detail.find("rollback failed"), std::string::npos);
    EXPECT_EQ(replace_calls, 2);
    bool kept_recovery_copy = false;
    for (const auto& entry : std::filesystem::directory_iterator(
             kasumi::test::workspace_root(workspace))) {
        if (entry.path().filename().string().starts_with(".kasumi-previous-")) {
            std::ifstream backup(entry.path(), std::ios::binary);
            const std::string body{std::istreambuf_iterator<char>{backup},
                                   std::istreambuf_iterator<char>{}};
            EXPECT_EQ(body, "old executable");
            kept_recovery_copy = true;
        }
    }
    EXPECT_TRUE(kept_recovery_copy);
}

TEST(CliUpdateTest,
     LinuxPrivilegedHandoffDoesNotAcceptArchiveOrDestinationArguments) {
#if !defined(_WIN32)
    std::vector<std::string> arguments{"kasumi",
                                       "--kasumi-update-install",
                                       "arbitrary/archive.tar.gz",
                                       "v999.0.0",
                                       "en",
                                       "arbitrary-destination"};
    std::vector<char*> argv;
    for (auto& argument : arguments) {
        argv.push_back(argument.data());
    }
    EXPECT_NE(
        kasumi::cli::update::run(static_cast<int>(argv.size()), argv.data()),
        0);
#endif
}

#if defined(__linux__)
TEST(CliUpdateTest, LinuxSystemToolResolutionUsesTrustedDirectories) {
    using namespace kasumi::cli::update;
    const auto resolved = resolve_linux_system_tool("tar");
    ASSERT_TRUE(resolved) << resolved.error();
    EXPECT_TRUE(resolved->is_absolute());
    const auto path = resolved->generic_string();
    EXPECT_TRUE(path.starts_with("/usr/bin/") || path.starts_with("/bin/") ||
                path.starts_with("/usr/local/bin/") ||
                path.starts_with("/usr/sbin/") || path.starts_with("/sbin/") ||
                path.starts_with("/usr/local/sbin/"));
    EXPECT_TRUE(validate_linux_system_tool(*resolved));
}

TEST(CliUpdateTest,
     LinuxSystemToolRejectsUserControlledExecutableAndDirectory) {
    using namespace kasumi::cli::update;
    if (::geteuid() == 0) {
        GTEST_SKIP()
            << "this ownership regression needs an unprivileged test process";
    }
    auto workspace = kasumi::test::make_temp_workspace("update-untrusted-tool");
    const auto tool = kasumi::test::workspace_path(workspace, "tar");
    {
        std::ofstream output(tool, std::ios::binary);
        output << "#!/bin/sh\nexit 0\n";
    }
    std::filesystem::permissions(tool,
                                 std::filesystem::perms::owner_all |
                                     std::filesystem::perms::group_exec |
                                     std::filesystem::perms::others_exec,
                                 std::filesystem::perm_options::replace);
    struct stat status{};
    ASSERT_EQ(::stat(tool.c_str(), &status), 0);
    EXPECT_EQ(status.st_uid, ::getuid());
    EXPECT_FALSE(validate_linux_system_tool(tool));
    EXPECT_FALSE(
        validate_linux_system_tool(kasumi::test::workspace_root(workspace)));
}

TEST(CliUpdateTest, LinuxModifiedPathCannotSelectPrivilegedTool) {
    using namespace kasumi::cli::update;
    auto workspace = kasumi::test::make_temp_workspace("update-hostile-path");
    const auto fake_bin = kasumi::test::workspace_path(workspace, "bin");
    ASSERT_TRUE(std::filesystem::create_directory(fake_bin));
    const auto fake_tar = fake_bin / "tar";
    {
        std::ofstream output(fake_tar, std::ios::binary);
        output << "#!/bin/sh\nexit 0\n";
    }
    std::filesystem::permissions(fake_tar,
                                 std::filesystem::perms::owner_all |
                                     std::filesystem::perms::group_exec |
                                     std::filesystem::perms::others_exec,
                                 std::filesystem::perm_options::replace);
    const char* old_path = std::getenv("PATH");
    const std::optional<std::string> saved_path =
        old_path == nullptr ? std::nullopt
                            : std::optional<std::string>{old_path};
    ASSERT_EQ(::setenv("PATH", fake_bin.c_str(), 1), 0);
    const auto resolved = resolve_linux_system_tool("tar");
    if (saved_path) {
        EXPECT_EQ(::setenv("PATH", saved_path->c_str(), 1), 0);
    } else {
        EXPECT_EQ(::unsetenv("PATH"), 0);
    }
    ASSERT_TRUE(resolved) << resolved.error();
    EXPECT_NE(*resolved, fake_tar);
    EXPECT_TRUE(validate_linux_system_tool(*resolved));
}

TEST(CliUpdateTest, LinuxMissingTrustedToolReturnsAnExplicitError) {
    const auto missing = kasumi::cli::update::resolve_linux_system_tool("apk");
    if (missing) {
        GTEST_SKIP() << "APK package manager is installed on this Linux image";
    }
    ASSERT_FALSE(missing);
    EXPECT_NE(missing.error().find("trusted system tool"), std::string::npos);
}

TEST(CliUpdateTest,
     LinuxToolValidationFailureCannotReachInstallOrChangeTarget) {
    using namespace kasumi::cli::update;
    auto workspace =
        kasumi::test::make_temp_workspace("update-tool-validation-failure");
    const auto package = package_names_for_this_platform();
    ASSERT_TRUE(package);
    const auto archive =
        kasumi::test::workspace_path(workspace, package->archive);
    const auto target = kasumi::test::workspace_path(workspace, "kasumi");
    {
        std::ofstream output(archive, std::ios::binary);
        output << "verified package";
    }
    {
        std::ofstream output(target, std::ios::binary);
        output << "original executable";
    }
    const auto digest = sha256_file(archive);
    ASSERT_TRUE(digest);
    int install_calls = 0;
    LinuxHandoffHooks hooks;
    hooks.fetch_checksum =
        [&](std::string_view) -> std::expected<std::string, std::string> {
        return *digest + "  " + package->archive + "\n";
    };
    hooks.prepare =
        [](const std::filesystem::path&,
           std::string_view) -> std::expected<PreparedExecutable, std::string> {
        const auto tool =
            resolve_linux_system_tool("kasumi-test-tool-that-does-not-exist");
        if (!tool) {
            return std::unexpected(tool.error());
        }
        return PreparedExecutable{};
    };
    hooks.install = [&](const PreparedExecutable&,
                        const std::filesystem::path&) -> InstallResult {
        ++install_calls;
        return {};
    };
    const auto result =
        install_linux_handoff(archive, "v0.99.0", target, hooks);
    ASSERT_FALSE(result);
    EXPECT_EQ(install_calls, 0);
    std::ifstream input(target, std::ios::binary);
    const std::string body{std::istreambuf_iterator<char>{input},
                           std::istreambuf_iterator<char>{}};
    EXPECT_EQ(body, "original executable");
}

TEST(CliUpdateTest, LinuxPkexecResultsDistinguishUnavailableAgentFromDenial) {
    using namespace kasumi::cli::update;
    EXPECT_EQ(classify_linux_pkexec_result(0, {}).state,
              LinuxElevationState::Succeeded);
    EXPECT_EQ(classify_linux_pkexec_result(126, "Request dismissed").state,
              LinuxElevationState::Cancelled);
    EXPECT_EQ(
        classify_linux_pkexec_result(127,
                                     "Error executing command as another user: "
                                     "No authentication agent found.\n")
            .state,
        LinuxElevationState::AuthenticationUnavailable);
    EXPECT_EQ(
        classify_linux_pkexec_result(
            127, "Error executing command as another user: Not authorized\n")
            .state,
        LinuxElevationState::Failed);
    EXPECT_EQ(classify_linux_pkexec_result(127, "unknown failure").state,
              LinuxElevationState::Failed);
}

TEST(CliUpdateTest, LinuxElevationUsesPkexecWhenItSucceeds) {
    using namespace kasumi::cli::update;
    int pkexec_calls = 0;
    int sudo_calls = 0;
    const auto result = attempt_linux_elevation(
        true,
        [&] {
            ++pkexec_calls;
            return LinuxElevationResult{LinuxElevationState::Succeeded, {}};
        },
        [&] {
            ++sudo_calls;
            return LinuxElevationResult{LinuxElevationState::Succeeded, {}};
        });
    EXPECT_EQ(result.state, LinuxElevationState::Succeeded);
    EXPECT_EQ(pkexec_calls, 1);
    EXPECT_EQ(sudo_calls, 0);
}

TEST(CliUpdateTest, LinuxElevationFallsBackToSudoWhenPkexecIsAbsent) {
    using namespace kasumi::cli::update;
    int sudo_calls = 0;
    const auto result = attempt_linux_elevation(true, {}, [&] {
        ++sudo_calls;
        return LinuxElevationResult{LinuxElevationState::Succeeded, {}};
    });
    EXPECT_EQ(result.state, LinuxElevationState::Succeeded);
    EXPECT_EQ(sudo_calls, 1);
}

TEST(CliUpdateTest, LinuxElevationFallsBackOnlyWhenPkexecAgentIsUnavailable) {
    using namespace kasumi::cli::update;
    int pkexec_calls = 0;
    int sudo_calls = 0;
    const auto result = attempt_linux_elevation(
        true,
        [&] {
            ++pkexec_calls;
            return LinuxElevationResult{
                LinuxElevationState::AuthenticationUnavailable,
                "no authentication agent"};
        },
        [&] {
            ++sudo_calls;
            return LinuxElevationResult{LinuxElevationState::Succeeded, {}};
        });
    EXPECT_EQ(result.state, LinuxElevationState::Succeeded);
    EXPECT_EQ(pkexec_calls, 1);
    EXPECT_EQ(sudo_calls, 1);
}

TEST(CliUpdateTest, LinuxElevationNeverFallsBackAfterDenialOrUncertainFailure) {
    using namespace kasumi::cli::update;
    for (const auto state :
         {LinuxElevationState::Cancelled, LinuxElevationState::Failed}) {
        int pkexec_calls = 0;
        int sudo_calls = 0;
        const auto result = attempt_linux_elevation(
            true,
            [&] {
                ++pkexec_calls;
                return LinuxElevationResult{state, "pkexec result"};
            },
            [&] {
                ++sudo_calls;
                return LinuxElevationResult{LinuxElevationState::Succeeded, {}};
            });
        EXPECT_EQ(result.state, state);
        EXPECT_EQ(pkexec_calls, 1);
        EXPECT_EQ(sudo_calls, 0);
    }
}

TEST(CliUpdateTest, LinuxElevationRequiresATerminalForSudoAndFailsWhenMissing) {
    using namespace kasumi::cli::update;
    int sudo_calls = 0;
    const auto no_pkexec = attempt_linux_elevation(false, {}, [&] {
        ++sudo_calls;
        return LinuxElevationResult{LinuxElevationState::Succeeded, {}};
    });
    EXPECT_EQ(no_pkexec.state, LinuxElevationState::Failed);
    EXPECT_EQ(sudo_calls, 0);
    const auto unavailable = attempt_linux_elevation(true, {}, {});
    EXPECT_EQ(unavailable.state, LinuxElevationState::Failed);
    EXPECT_NE(unavailable.detail.find("unavailable"), std::string::npos);
}

TEST(CliUpdateTest, LinuxElevationDoesNotRepeatAndCancellationPreservesTarget) {
    using namespace kasumi::cli::update;
    auto workspace =
        kasumi::test::make_temp_workspace("update-elevation-cancel");
    const auto target = kasumi::test::workspace_path(workspace, "kasumi");
    const auto prepared = kasumi::test::workspace_path(workspace, "prepared");
    {
        std::ofstream output(target, std::ios::binary);
        output << "original executable";
    }
    {
        std::ofstream output(prepared, std::ios::binary);
        output << "verified executable";
    }
    const auto digest = sha256_file(prepared);
    ASSERT_TRUE(digest);
    InstallHooks install_hooks;
    install_hooks.replace_atomically =
        [](const auto&, const auto&) -> std::expected<void, std::string> {
        return std::unexpected(
            "replace_atomically failed (native_code=13): permission denied");
    };
    int pkexec_calls = 0;
    int sudo_calls = 0;
    const auto result = install_once_then_elevate(
        [&] {
            return install_prepared_executable(
                prepared, target, *digest, &install_hooks);
        },
        [&]() -> InstallResult {
            const auto denied = attempt_linux_elevation(
                true,
                [&] {
                    ++pkexec_calls;
                    return LinuxElevationResult{LinuxElevationState::Cancelled,
                                                "authorization cancelled"};
                },
                [&] {
                    ++sudo_calls;
                    return LinuxElevationResult{LinuxElevationState::Succeeded,
                                                {}};
                });
            return std::unexpected(
                InstallFailure{InstallFailure::Kind::Other, denied.detail});
        });
    ASSERT_FALSE(result);
    EXPECT_EQ(pkexec_calls, 1);
    EXPECT_EQ(sudo_calls, 0);
    std::ifstream input(target, std::ios::binary);
    const std::string body{std::istreambuf_iterator<char>{input},
                           std::istreambuf_iterator<char>{}};
    EXPECT_EQ(body, "original executable");
}

TEST(CliUpdateTest, LinuxPrivilegedHandoffOnlyFetchesOfficialChecksum) {
    using namespace kasumi::cli::update;
    auto workspace = kasumi::test::make_temp_workspace("update-linux-handoff");
    const auto package = package_names_for_this_platform();
    ASSERT_TRUE(package);
    const auto archive =
        kasumi::test::workspace_path(workspace, package->archive);
    {
        std::ofstream output(archive, std::ios::binary);
        output << "verified package";
    }
    const auto digest = sha256_file(archive);
    ASSERT_TRUE(digest);
    int checksum_requests = 0;
    int prepare_calls = 0;
    int install_calls = 0;
    LinuxHandoffHooks hooks;
    hooks.fetch_checksum =
        [&](std::string_view url) -> std::expected<std::string, std::string> {
        ++checksum_requests;
        EXPECT_EQ(url,
                  "https://github.com/auanK/kasumi/releases/download/v0.99.0/" +
                      package->checksum);
        return *digest + "  " + package->archive + "\n";
    };
    hooks.prepare = [&](const std::filesystem::path& source,
                        std::string_view expected)
        -> std::expected<PreparedExecutable, std::string> {
        ++prepare_calls;
        EXPECT_EQ(source, archive);
        EXPECT_EQ(expected, *digest);
        return PreparedExecutable{.path = source, .sha256 = *digest};
    };
    hooks.install = [&](const PreparedExecutable& prepared,
                        const std::filesystem::path& target) -> InstallResult {
        ++install_calls;
        EXPECT_EQ(prepared.path, archive);
        EXPECT_EQ(target, kasumi::test::workspace_path(workspace, "kasumi"));
        return {};
    };

    const auto result =
        install_linux_handoff(archive,
                              "v0.99.0",
                              kasumi::test::workspace_path(workspace, "kasumi"),
                              hooks);

    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(checksum_requests, 1);
    EXPECT_EQ(prepare_calls, 1);
    EXPECT_EQ(install_calls, 1);
}

TEST(CliUpdateTest,
     LinuxPrivilegedHandoffRejectsUnauthenticatedOrStalePackage) {
    using namespace kasumi::cli::update;
    auto workspace =
        kasumi::test::make_temp_workspace("update-linux-invalid-handoff");
    const auto package = package_names_for_this_platform();
    ASSERT_TRUE(package);
    const auto archive =
        kasumi::test::workspace_path(workspace, package->archive);
    {
        std::ofstream output(archive, std::ios::binary);
        output << "tampered package";
    }
    int prepare_calls = 0;
    LinuxHandoffHooks hooks;
    hooks.fetch_checksum =
        [](std::string_view) -> std::expected<std::string, std::string> {
        return std::string(64, 'a') + "  kasumi-linux-x86_64.tar.gz\n";
    };
    hooks.prepare = [&](const std::filesystem::path&, std::string_view)
        -> std::expected<PreparedExecutable, std::string> {
        ++prepare_calls;
        return std::unexpected("should not prepare an unauthenticated package");
    };
    hooks.install = [](const PreparedExecutable&,
                       const std::filesystem::path&) -> InstallResult {
        return {};
    };

    EXPECT_FALSE(
        install_linux_handoff(archive,
                              "v0.99.0",
                              kasumi::test::workspace_path(workspace, "kasumi"),
                              hooks));
    EXPECT_FALSE(
        install_linux_handoff(archive,
                              "not-a-tag",
                              kasumi::test::workspace_path(workspace, "kasumi"),
                              hooks));
    EXPECT_EQ(prepare_calls, 0);
}
#endif

#if !defined(_WIN32)
TEST(CliUpdateTest, InstallsIntoAnOwnedTemporaryDirectoryWithoutRootChown) {
    if (::geteuid() == 0) {
        GTEST_SKIP()
            << "this ownership regression needs an unprivileged test process";
    }
    auto workspace = kasumi::test::make_temp_workspace("update-unprivileged");
    const auto target = kasumi::test::workspace_path(workspace, "kasumi");
    const auto prepared = kasumi::test::workspace_path(workspace, "prepared");
    {
        std::ofstream output(target, std::ios::binary);
        output << "old executable";
    }
    {
        std::ofstream output(prepared, std::ios::binary);
        output << "new executable";
    }
    struct stat before{};
    ASSERT_EQ(::stat(target.c_str(), &before), 0);
    const auto digest = kasumi::cli::update::sha256_file(prepared);
    ASSERT_TRUE(digest);

    const auto installed = kasumi::cli::update::install_prepared_executable(
        prepared, target, *digest);

    ASSERT_TRUE(installed.has_value()) << installed.error().detail;
    struct stat after{};
    ASSERT_EQ(::stat(target.c_str(), &after), 0);
    EXPECT_EQ(after.st_uid, before.st_uid);
    EXPECT_EQ(after.st_gid, before.st_gid);
}
#endif

#if defined(_WIN32)
TEST(CliUpdateTest, WindowsWorkspaceGrantsAdministratorsReadOnlyAccess) {
    auto workspace = kasumi::platform::create_workspace("admin-read-test");
    ASSERT_TRUE(workspace);
    const auto root = workspace->root;
    const auto granted =
        kasumi::cli::update::grant_windows_admin_read_access(root);
    ASSERT_TRUE(granted) << granted.error();
    EXPECT_TRUE(kasumi::cli::update::validate_windows_workspace_acl(root));
    kasumi::platform::cleanup_workspace(*workspace);
}

TEST(CliUpdateTest, WindowsDestinationIdentityRejectsAnotherKasumiExecutable) {
    auto workspace =
        kasumi::test::make_temp_workspace("update-windows-identity");
    const auto original = kasumi::test::workspace_path(workspace, "kasumi.exe");
    const auto alternate =
        kasumi::test::workspace_path(workspace, "other-kasumi.exe");
    {
        std::ofstream output(original, std::ios::binary);
        output << "first executable";
    }
    {
        std::ofstream output(alternate, std::ios::binary);
        output << "first executable";
    }
    const auto identity = kasumi::cli::update::windows_file_identity(original);
    ASSERT_TRUE(identity);
    EXPECT_EQ(kasumi::cli::update::sha256_file(original),
              kasumi::cli::update::sha256_file(alternate));
    EXPECT_TRUE(kasumi::cli::update::windows_file_identity_matches(original,
                                                                   *identity));
    EXPECT_FALSE(kasumi::cli::update::windows_file_identity_matches(alternate,
                                                                    *identity));
    const auto moved = kasumi::test::workspace_path(workspace, "previous.exe");
    std::error_code error;
    std::filesystem::rename(original, moved, error);
    ASSERT_FALSE(error) << error.message();
    {
        std::ofstream output(original, std::ios::binary);
        output << "replacement executable";
    }
    EXPECT_FALSE(kasumi::cli::update::windows_file_identity_matches(original,
                                                                    *identity));
}

TEST(CliUpdateTest, WindowsInstallerRejectsDestinationChangedDuringHandoff) {
    using namespace kasumi::cli::update;
    auto workspace =
        kasumi::test::make_temp_workspace("update-windows-target-change");
    const auto target = kasumi::test::workspace_path(workspace, "kasumi.exe");
    const auto prepared =
        kasumi::test::workspace_path(workspace, "prepared.exe");
    {
        std::ofstream output(target, std::ios::binary);
        output << "original installation";
    }
    {
        std::ofstream output(prepared, std::ios::binary);
        output << "verified update";
    }
    const auto identity = windows_file_identity(target);
    const auto digest = sha256_file(prepared);
    ASSERT_TRUE(identity && digest);
    const auto previous =
        kasumi::test::workspace_path(workspace, "previous.exe");
    std::error_code error;
    std::filesystem::rename(target, previous, error);
    ASSERT_FALSE(error) << error.message();
    {
        std::ofstream output(target, std::ios::binary);
        output << "replacement installation";
    }
    InstallHooks hooks;
    hooks.validate_target =
        [identity = *identity](const std::filesystem::path& candidate)
        -> std::expected<void, std::string> {
        if (!windows_file_identity_matches(candidate, identity)) {
            return std::unexpected("target identity changed");
        }
        return {};
    };

    const auto installed =
        install_prepared_executable(prepared, target, *digest, &hooks);

    ASSERT_FALSE(installed);
    std::ifstream input(target, std::ios::binary);
    const std::string body{std::istreambuf_iterator<char>{input},
                           std::istreambuf_iterator<char>{}};
    EXPECT_EQ(body, "replacement installation");
}

TEST(CliUpdateTest, WindowsInternalArgumentsRoundTripUnicodePaths) {
    using kasumi::cli::update::windows_decode_arguments;
    using kasumi::cli::update::windows_join_arguments;
    const std::vector<std::wstring> arguments{
        L"kasumi update helper",
        L"--kasumi-update-helper",
        L"C:\\Users\\João\\Program Files\\Aplicações\\Kasumi\\archive.zip",
        L"--language=pt-BR"};
    const auto command_line = windows_join_arguments(arguments);
    const auto decoded = windows_decode_arguments(command_line);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, arguments);
}
#endif
