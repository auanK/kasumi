#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "runtime/paths.hpp"
#include "runtime/profile.hpp"

#include <array>
#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

using kasumi::test::TempWorkspace;

TEST(RuntimePathsTest, GlobalPathsArePureAndProfilePathsStayUnderProfiles) {
    auto workspace = kasumi::test::make_temp_workspace("runtime-paths");
    const auto paths = kasumi::runtime::global_paths_from_root(
        kasumi::test::workspace_path(workspace, "app data"));
    EXPECT_FALSE(std::filesystem::exists(paths.app_data_dir));
    EXPECT_EQ(paths.config_path, paths.app_data_dir / "config.toml");
    EXPECT_EQ(paths.profiles_dir, paths.app_data_dir / "profiles");

    const auto resolved = kasumi::runtime::resolve_profile_paths(
        kasumi::test::workspace_path(workspace, "app data"), "café");
    EXPECT_FALSE(resolved.has_value());
    const auto valid = kasumi::runtime::resolve_profile_paths(
        kasumi::test::workspace_path(workspace, "app data"), "desktop-01");
    ASSERT_TRUE(valid.has_value());
    EXPECT_EQ(valid->profile_dir.parent_path(), paths.profiles_dir);
    EXPECT_EQ(valid->database_path, valid->profile_dir / "db.sqlite");
    EXPECT_EQ(valid->key_path, valid->profile_dir / "key.bin");
}

TEST(RuntimePathsTest, ProfileNamesAcceptOnlyPortableIdentifiers) {
    constexpr std::array valid{"main", "desktop-01", "A_2", "x"};
    constexpr std::array invalid{
        "", ".", "..", "a/b", "a\\b", "a b", "a.b", "..hidden", "a\t", "é"};
    for (const auto name : valid)
        EXPECT_TRUE(kasumi::runtime::is_valid_profile_name(name)) << name;
    for (const auto name : invalid)
        EXPECT_FALSE(kasumi::runtime::is_valid_profile_name(name)) << name;
    EXPECT_TRUE(kasumi::runtime::is_valid_profile_name(std::string(64, 'a')));
}

TEST(RuntimePathsTest, ProfileDirectoryOperationsAreIdempotent) {
    auto workspace = kasumi::test::make_temp_workspace("runtime-profile-dir");
    const auto paths = *kasumi::runtime::resolve_profile_paths(
        kasumi::test::workspace_root(workspace), "profile");
    EXPECT_TRUE(kasumi::runtime::ensure_profile_directory(paths));
    EXPECT_TRUE(kasumi::runtime::ensure_profile_directory(paths));
    EXPECT_TRUE(std::filesystem::is_directory(paths.profile_dir));

    const auto renamed = *kasumi::runtime::resolve_profile_paths(
        kasumi::test::workspace_root(workspace), "renamed");
    EXPECT_TRUE(kasumi::runtime::rename_profile_directory(paths, renamed));
    EXPECT_TRUE(std::filesystem::is_directory(renamed.profile_dir));
    EXPECT_TRUE(kasumi::runtime::remove_profile_directory(renamed));
    EXPECT_TRUE(kasumi::runtime::remove_profile_directory(renamed));
    EXPECT_FALSE(std::filesystem::exists(renamed.profile_dir));
}

TEST(RuntimeProfileTest, ProfilesRoundTripAndMissingProfileAreReported) {
    auto workspace =
        kasumi::test::make_temp_workspace("runtime-profile-config");
    const auto config = kasumi::test::workspace_path(workspace, "config.toml");
    const std::vector<kasumi::runtime::ProfileData> profiles{
        {"one",
         kasumi::test::workspace_path(workspace, "local one"),
         "remote one:"},
        {"two",
         kasumi::test::workspace_path(workspace, kasumi::platform::path::from_utf8("local-é")),
         "relative/path"}};
    ASSERT_TRUE(kasumi::runtime::save_profiles(config, profiles));
    const auto loaded = kasumi::runtime::load_profiles(config);
    ASSERT_TRUE(loaded.has_value());
    ASSERT_EQ(loaded->size(), 2U);
    EXPECT_EQ(loaded->at(0).name, "one");
    EXPECT_EQ(loaded->at(1).local_dir,
              kasumi::test::workspace_path(workspace, kasumi::platform::path::from_utf8("local-é")));
    EXPECT_TRUE(kasumi::runtime::load_profile(config, "one"));
    const auto absent = kasumi::runtime::load_profile(config, "missing");
    ASSERT_FALSE(absent.has_value());
    EXPECT_EQ(absent.error().code, kasumi::runtime::ErrorCode::ProfileNotFound);
}

TEST(RuntimeProfileTest, UnicodeFilesystemPathsSurvivePersistence) {
    namespace path = kasumi::platform::path;
    auto workspace = kasumi::test::make_temp_workspace("unicode-profile");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto directory = root / path::from_utf8("configuração-高松灯🌸");
    std::filesystem::create_directories(directory);
    const auto config = directory / path::from_utf8("千早愛音💝.toml");
    const auto local = root / path::from_utf8("pasta-日本/usuário-☁/𝑬𝒎𝒊𝒍𝒊𝒂/𓆩🌸𓆪");
    const auto remote = path::to_utf8(root / path::from_utf8("Backup/高松灯"));
    const std::vector<kasumi::runtime::ProfileData> profiles{
        {.name = "unicode", .local_dir = local, .remote_dir = remote}};
    const auto saved = kasumi::runtime::save_profiles(config, profiles);
    ASSERT_TRUE(saved) << saved.error().detail;
    const auto loaded = kasumi::runtime::load_profile(config, "unicode");
    ASSERT_TRUE(loaded) << loaded.error().detail;
    EXPECT_EQ(loaded->local_dir, local);
    EXPECT_EQ(path::to_utf8(loaded->local_dir), path::to_utf8(local));
    EXPECT_EQ(loaded->remote_dir, remote);
    const auto rewritten = kasumi::runtime::save_profiles(config, profiles);
    ASSERT_TRUE(rewritten) << rewritten.error().detail;
    const auto reloaded = kasumi::runtime::load_profile(config, "unicode");
    ASSERT_TRUE(reloaded) << reloaded.error().detail;
    EXPECT_EQ(reloaded->local_dir, local);
    EXPECT_EQ(std::distance(std::filesystem::directory_iterator(directory),
                            std::filesystem::directory_iterator{}), 1);
}

TEST(RuntimeProfileTest, ConfigErrorsAndEmptyProfilesHaveSpecificCodes) {
    auto workspace =
        kasumi::test::make_temp_workspace("runtime-profile-errors");
    const auto missing = kasumi::runtime::load_profiles(
        kasumi::test::workspace_path(workspace, "none"));
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code, kasumi::runtime::ErrorCode::ConfigNotFound);

    const auto invalid =
        kasumi::test::workspace_path(workspace, "invalid.toml");
    kasumi::test::write_text(invalid, "[[broken");
    EXPECT_EQ(kasumi::runtime::load_profiles(invalid).error().code,
              kasumi::runtime::ErrorCode::ConfigInvalid);

    const auto empty = kasumi::test::workspace_path(workspace, "empty.toml");
    kasumi::test::write_text(empty, "");
    const auto no_profiles = kasumi::runtime::load_profiles(empty);
    ASSERT_TRUE(no_profiles.has_value());
    EXPECT_TRUE(no_profiles->empty());

    const auto malformed =
        kasumi::test::workspace_path(workspace, "malformed.toml");
    kasumi::test::write_text(malformed, "[profiles]\nfoo = 'scalar'\n");
    EXPECT_EQ(kasumi::runtime::load_profiles(malformed).error().code,
              kasumi::runtime::ErrorCode::ProfileInvalid);
}

TEST(RuntimeProfileTest, RetentionFieldsAreRequiredAndRejectInvalidValues) {
    auto workspace =
        kasumi::test::make_temp_workspace("runtime-retention-policy");
    const auto config = kasumi::test::workspace_path(workspace, "config.toml");
    const auto prefix =
        "[profiles.demo]\nlocal_dir = '" +
        kasumi::platform::path::to_utf8(
            kasumi::test::workspace_path(workspace, "local")) +
        "'\nremote_dir = 'remote:root'\n";

    kasumi::test::write_text(config, prefix);
    const auto missing = kasumi::runtime::load_profile(config, "demo");
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code, kasumi::runtime::ErrorCode::ProfileInvalid);

    kasumi::test::write_text(
        config, prefix + "min_history_depth = 5\nmin_history_age_hours = 6\n");
    const auto valid = kasumi::runtime::load_profile(config, "demo");
    ASSERT_TRUE(valid.has_value());
    EXPECT_EQ(valid->min_history_depth, 5U);
    EXPECT_EQ(valid->min_history_age_hours, 6U);

    for (const auto value : {"0", "-1", "4294967296", "'5'", "5.0"}) {
        SCOPED_TRACE(value);
        kasumi::test::write_text(config,
                                 prefix + "min_history_depth = " + value +
                                     "\nmin_history_age_hours = 6\n");
        const auto rejected = kasumi::runtime::load_profiles(config);
        ASSERT_FALSE(rejected.has_value());
        EXPECT_EQ(rejected.error().code,
                  kasumi::runtime::ErrorCode::ProfileInvalid);
    }
}

TEST(RuntimeProfileTest, SaveRejectsZeroWithoutCreatingPartialConfig) {
    auto workspace = kasumi::test::make_temp_workspace("runtime-save-policy");
    const auto config =
        kasumi::test::workspace_path(workspace, "missing-parent/config.toml");
    const std::vector<kasumi::runtime::ProfileData> profiles{
        {.name = "demo",
         .local_dir = kasumi::test::workspace_path(workspace, "local"),
         .remote_dir = "remote:root",
         .min_history_depth = 0,
         .min_history_age_hours = 6}};

    const auto saved = kasumi::runtime::save_profiles(config, profiles);
    ASSERT_FALSE(saved.has_value());
    EXPECT_EQ(saved.error().code, kasumi::runtime::ErrorCode::ProfileInvalid);
    EXPECT_FALSE(std::filesystem::exists(config));
    EXPECT_FALSE(std::filesystem::exists(config.parent_path()));
}

TEST(RuntimePathsTest, DefaultPathsRestoreEnvironmentOverrides) {
    auto workspace = kasumi::test::make_temp_workspace("runtime-env");
#if defined(_WIN32)
    auto scoped = kasumi::test::scoped_environment_variable(
        "APPDATA",
        kasumi::platform::path::to_utf8(
            kasumi::test::workspace_path(workspace, "appdata")));
    const auto paths = kasumi::runtime::default_global_paths();
    EXPECT_EQ(paths.app_data_dir,
              kasumi::test::workspace_path(workspace, "appdata") / "kasumi");
#else
    auto scoped = kasumi::test::scoped_environment_variable(
        "XDG_CONFIG_HOME",
        kasumi::platform::path::to_utf8(
            kasumi::test::workspace_path(workspace, "xdg")));
    const auto paths = kasumi::runtime::default_global_paths();
    EXPECT_EQ(paths.app_data_dir,
              kasumi::test::workspace_path(workspace, "xdg") / "kasumi");
#endif
    EXPECT_FALSE(std::filesystem::exists(paths.app_data_dir));
}

#if defined(_WIN32)
TEST(RuntimePathsTest, AppDataWithUnicodeCharactersIsPreserved) {
    auto workspace =
        kasumi::test::make_temp_workspace("runtime-env-unicode");
    const auto unicode_appdata =
        kasumi::test::workspace_root(workspace) /
        kasumi::platform::path::from_utf8("usuário-João-日本");

    {
        const auto env = kasumi::test::scoped_windows_environment_variable(
            L"APPDATA", unicode_appdata.native());
        const auto paths = kasumi::runtime::default_global_paths();
        EXPECT_EQ(paths.app_data_dir, unicode_appdata / "kasumi");
        EXPECT_EQ(paths.config_path,
                  unicode_appdata / "kasumi" / "config.toml");
        EXPECT_EQ(paths.profiles_dir,
                  unicode_appdata / "kasumi" / "profiles");
    }
}

TEST(RuntimePathsTest, MissingAppDataFallsBackToCurrentPath) {
    {
        const auto env = kasumi::test::scoped_windows_environment_variable(
            L"APPDATA", std::nullopt);
        const auto paths = kasumi::runtime::default_global_paths();
        const auto expected_root =
            std::filesystem::current_path() / ".kasumi_data";
        EXPECT_EQ(paths.app_data_dir, expected_root);
        EXPECT_EQ(paths.config_path, expected_root / "config.toml");
        EXPECT_EQ(paths.profiles_dir, expected_root / "profiles");
        EXPECT_FALSE(std::filesystem::exists(paths.app_data_dir));
    }
}

TEST(RuntimePathsTest, EmptyAppDataFallsBackToCurrentPath) {
    {
        const auto env = kasumi::test::scoped_windows_environment_variable(
            L"APPDATA", std::wstring{L""});
        const auto paths = kasumi::runtime::default_global_paths();
        const auto expected_root =
            std::filesystem::current_path() / ".kasumi_data";
        EXPECT_EQ(paths.app_data_dir, expected_root);
        EXPECT_EQ(paths.config_path, expected_root / "config.toml");
        EXPECT_EQ(paths.profiles_dir, expected_root / "profiles");
        EXPECT_FALSE(std::filesystem::exists(paths.app_data_dir));
    }
}
#endif

} // namespace
