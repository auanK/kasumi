#include "application/profile.hpp"
#include "application/sync/journal.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/private_storage.hpp"
#include "runtime/paths.hpp"
#include "runtime/profile.hpp"
#include "state_storage/database_connection.hpp"
#include "state_storage/database.hpp"

#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <utility>

#include "application/profile_fault_test.hpp"
#include "platform/profile_lock.hpp"
#include "runtime/vault.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string_view>
#include <system_error>
#include <sqlite3.h>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#else
#include <sys/stat.h>
#endif
namespace {

using kasumi::application::ExecutionEnvironment;
using kasumi::application::MasterKeyHex;
using kasumi::application::Profile;
using kasumi::application::ProfileCredentials;
using kasumi::test::TempWorkspace;

struct TestDirectoryIdentity {
#if defined(_WIN32)
    std::uint64_t volume = 0;
    std::uint64_t low = 0;
    std::uint64_t high = 0;
#else
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
#endif
    bool valid = false;
    bool operator==(const TestDirectoryIdentity&) const = default;
};

TestDirectoryIdentity test_directory_identity(
    const std::filesystem::path& path) noexcept {
    TestDirectoryIdentity result;
#if defined(_WIN32)
    const auto handle = CreateFileW(path.c_str(),
                                    FILE_READ_ATTRIBUTES,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE |
                                        FILE_SHARE_DELETE,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_FLAG_BACKUP_SEMANTICS |
                                        FILE_FLAG_OPEN_REPARSE_POINT,
                                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return result;
    }
    FILE_ID_INFO info{};
    if (GetFileInformationByHandleEx(handle, FileIdInfo, &info, sizeof(info))) {
        result.volume = info.VolumeSerialNumber;
        std::memcpy(&result.low,
                    info.FileId.Identifier,
                    sizeof(result.low));
        std::memcpy(&result.high,
                    info.FileId.Identifier + sizeof(result.low),
                    sizeof(result.high));
        result.valid = true;
    }
    CloseHandle(handle);
#else
    struct stat status {};
    if (::lstat(path.c_str(), &status) == 0 && S_ISDIR(status.st_mode)) {
        result.device = static_cast<std::uint64_t>(status.st_dev);
        result.inode = static_cast<std::uint64_t>(status.st_ino);
        result.valid = true;
    }
#endif
    return result;
}

MasterKeyHex key() {
    return MasterKeyHex{std::string(64, '1')};
}

struct FileReplacementEvidence {
    kasumi::platform::private_storage::FileIdentity original;
    kasumi::platform::private_storage::FileIdentity replacement;
    bool completed = false;
};

FileReplacementEvidence replace_file(
    const std::filesystem::path& path,
    const std::filesystem::path& staged_path,
    std::string_view replacement_contents) {
    using kasumi::platform::private_storage::query_file_identity;
    FileReplacementEvidence evidence;
    evidence.original = query_file_identity(path);
    {
        std::ofstream stream(staged_path, std::ios::binary);
        stream.write(replacement_contents.data(),
                     static_cast<std::streamsize>(replacement_contents.size()));
        if (!stream) {
            return evidence;
        }
    }
    const auto staged_identity = query_file_identity(staged_path);
    if (!evidence.original.valid || !staged_identity.valid ||
        evidence.original == staged_identity) {
        return evidence;
    }
    std::error_code error;
    if (!std::filesystem::remove(path, error) || error) {
        return evidence;
    }
    std::filesystem::rename(staged_path, path, error);
    if (error) {
        return evidence;
    }
    evidence.replacement = query_file_identity(path);
    evidence.completed = evidence.replacement == staged_identity &&
                         evidence.replacement != evidence.original;
    return evidence;
}

bool install_file(const std::filesystem::path& path,
                  const std::filesystem::path& staged_path,
                  std::string_view contents) {
    {
        std::ofstream stream(staged_path, std::ios::binary);
        stream.write(contents.data(),
                     static_cast<std::streamsize>(contents.size()));
        if (!stream) {
            return false;
        }
    }
    std::error_code error;
    std::filesystem::rename(staged_path, path, error);
    return !error &&
           kasumi::platform::private_storage::query_file_identity(path).valid;
}

#if defined(_WIN32)
bool create_directory_junction(const std::filesystem::path& link,
                               const std::filesystem::path& target,
                               std::error_code& error) {
    if (!std::filesystem::create_directory(link, error)) {
        return false;
    }
    const auto handle = CreateFileW(link.c_str(),
                                    GENERIC_WRITE,
                                    0,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_FLAG_BACKUP_SEMANTICS |
                                        FILE_FLAG_OPEN_REPARSE_POINT,
                                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        error = std::error_code{static_cast<int>(GetLastError()),
                                std::system_category()};
        std::error_code ignored;
        std::filesystem::remove(link, ignored);
        return false;
    }

    struct MountPointReparseData {
        DWORD tag;
        WORD data_length;
        WORD reserved;
        WORD substitute_offset;
        WORD substitute_length;
        WORD print_offset;
        WORD print_length;
        wchar_t path_buffer[1];
    };
    auto substitute = std::wstring{L"\\??\\"} + target.native();
    const auto printable = target.native();
    const auto substitute_bytes = substitute.size() * sizeof(wchar_t);
    const auto printable_bytes = printable.size() * sizeof(wchar_t);
    const auto path_bytes = substitute_bytes + sizeof(wchar_t) +
                            printable_bytes + sizeof(wchar_t);
    const auto header_bytes = offsetof(MountPointReparseData, path_buffer);
    std::vector<std::byte> buffer(header_bytes + path_bytes);
    auto* data = reinterpret_cast<MountPointReparseData*>(buffer.data());
    data->tag = IO_REPARSE_TAG_MOUNT_POINT;
    data->data_length = static_cast<WORD>(8 + path_bytes);
    data->reserved = 0;
    data->substitute_offset = 0;
    data->substitute_length = static_cast<WORD>(substitute_bytes);
    data->print_offset = static_cast<WORD>(substitute_bytes + sizeof(wchar_t));
    data->print_length = static_cast<WORD>(printable_bytes);
    std::memcpy(data->path_buffer, substitute.data(), substitute_bytes);
    data->path_buffer[substitute.size()] = L'\0';
    std::memcpy(data->path_buffer + substitute.size() + 1,
                printable.data(),
                printable_bytes);
    data->path_buffer[substitute.size() + 1 + printable.size()] = L'\0';
    DWORD returned = 0;
    const bool created = DeviceIoControl(handle,
                                         FSCTL_SET_REPARSE_POINT,
                                         data,
                                         static_cast<DWORD>(buffer.size()),
                                         nullptr,
                                         0,
                                         &returned,
                                         nullptr) != 0;
    const auto code = created ? ERROR_SUCCESS : GetLastError();
    CloseHandle(handle);
    if (!created) {
        error = std::error_code{static_cast<int>(code), std::system_category()};
        std::error_code ignored;
        std::filesystem::remove(link, ignored);
        return false;
    }
    return true;
}
#endif

void expect_clone_rollback_preserves_substituted_file(
    std::string_view fixture_name,
    std::string_view relative_path,
    std::string_view replacement_contents) {
    auto workspace = kasumi::test::make_temp_workspace(fixture_name);
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile source{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, source, key()));
    const auto destination = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(destination.has_value());
    const auto replaced_path =
        destination->profile_dir / std::filesystem::path(relative_path);
    const auto staged_path =
        kasumi::test::workspace_path(workspace, "replacement.bin");

    TestDirectoryIdentity directory_identity;
    FileReplacementEvidence replacement;
    bool reached_failure = false;
    {
        kasumi::application::fault_test::ScopedCloneFaultInjection fault(
            kasumi::application::fault_test::CloneFaultStage::FailConfigSave,
            [&](kasumi::application::fault_test::CloneFaultStage) {
                reached_failure = true;
                directory_identity =
                    test_directory_identity(destination->profile_dir);
                replacement = replace_file(
                    replaced_path, staged_path, replacement_contents);
            });
        const auto result = kasumi::application::clone_profile(
            environment, "source", "destination");
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code,
                  kasumi::application::ProfileErrorCode::ConfigFailure);
        EXPECT_NE(result.error().detail.find("rollback also failed"),
                  std::string::npos);
    }

    EXPECT_TRUE(reached_failure);
    ASSERT_TRUE(directory_identity.valid);
    ASSERT_TRUE(replacement.completed);
    EXPECT_EQ(test_directory_identity(destination->profile_dir),
              directory_identity);
    EXPECT_EQ(kasumi::platform::private_storage::query_file_identity(
                  replaced_path),
              replacement.replacement);
    std::ifstream stream(replaced_path, std::ios::binary);
    const std::string actual{std::istreambuf_iterator<char>(stream),
                             std::istreambuf_iterator<char>()};
    EXPECT_EQ(actual, replacement_contents);
}

bool save_height(const std::filesystem::path& database_path,
                 std::uint64_t height) {
    kasumi::Snapshot tree{{
        {.path = "", .is_directory = true},
        {.path = "accepted.txt",
         .hash = kasumi::hasher::hash_string("accepted"),
         .size = 8,
         .mtime = 1,
         .is_directory = false},
    }};
    kasumi::finalize_snapshot(tree);
    return kasumi::state_storage::save_state(
        database_path,
        kasumi::state_storage::StoredState{
            .tree = std::move(tree),
            .height = height,
            .commit_id =
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        });
}

TEST(ApplicationProfileTest, ListMissingConfigIsEmptyAndCreateListsProfile) {
    auto workspace = kasumi::test::make_temp_workspace("application-profile");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const auto before = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(before.has_value());
    EXPECT_TRUE(before->empty());

    const Profile profile{
        "main",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));
    const auto listed = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(listed.has_value());
    ASSERT_EQ(listed->size(), 1U);
    EXPECT_EQ(listed->front().name, "main");
    EXPECT_TRUE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles/main/key.bin")));
    const auto paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "main");
    ASSERT_TRUE(paths.has_value());
    EXPECT_TRUE(kasumi::state_storage::validate(paths->database_path));
}

TEST(ApplicationProfileTest, RejectsDuplicateNames) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-profile-errors");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "main",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));
    const auto duplicate =
        kasumi::application::create_profile(environment, profile, key());
    ASSERT_FALSE(duplicate.has_value());
    EXPECT_EQ(duplicate.error().code,
              kasumi::application::ProfileErrorCode::AlreadyExists);
    const Profile invalid{
        "../escape",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    EXPECT_EQ(kasumi::application::create_profile(environment, invalid, key())
                  .error()
                  .code,
              kasumi::application::ProfileErrorCode::InvalidName);
}

TEST(ApplicationProfileTest,
     UnsupportedConfigFieldsAreRejectedWithoutOverwritingThem) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-profile-unknown-config");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    std::filesystem::create_directories(environment.app_data_dir);
    const auto config = environment.app_data_dir / "config.toml";
    const std::string original =
        "format_version = 99\n"
        "[profiles.existing]\n"
        "local_dir = '/tmp/existing'\n"
        "remote_dir = '/tmp/remote'\n"
        "min_history_depth = 5\n"
        "min_history_age_hours = 6\n"
        "future_option = true\n";
    kasumi::test::write_text(config, original);

    const auto result = kasumi::application::create_profile(
        environment,
        Profile{"new",
                kasumi::test::workspace_path(workspace, "local"),
                kasumi::test::workspace_path(workspace, "remote").string()},
        key());

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(kasumi::test::read_text(config), original);
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles/new")));
}

TEST(ApplicationProfileTest, UnknownProfileFieldsAreRejectedOnLoad) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-profile-unknown-field");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    std::filesystem::create_directories(environment.app_data_dir);
    const auto config = environment.app_data_dir / "config.toml";
    kasumi::test::write_text(
        config,
        "[profiles.demo]\n"
        "local_dir = '/tmp/local'\n"
        "remote_dir = '/tmp/remote'\n"
        "min_history_depth = 5\n"
        "min_history_age_hours = 6\n"
        "future_option = true\n");

    const auto result =
        kasumi::runtime::load_profiles(config);

    EXPECT_FALSE(result.has_value());
}

TEST(ApplicationProfileTest, RejectsRelativeLocalAndStoragePaths) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-profile-paths");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const auto relative_local = kasumi::application::create_profile(
        environment, Profile{"local", "relative", "remote:root"}, key());
    ASSERT_FALSE(relative_local.has_value());
    EXPECT_EQ(relative_local.error().code,
              kasumi::application::ProfileErrorCode::StorageFailure);

    const auto relative_storage = kasumi::application::create_profile(
        environment,
        Profile{"storage",
                kasumi::test::workspace_path(workspace, "local"),
                "relative"},
        key());
    ASSERT_FALSE(relative_storage.has_value());
    EXPECT_EQ(relative_storage.error().code,
              kasumi::application::ProfileErrorCode::StorageFailure);
}

TEST(ApplicationProfileTest, InvalidRetentionDoesNotCreateProfileArtifacts) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-profile-retention");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile invalid{
        .name = "demo",
        .local_dir = kasumi::test::workspace_path(workspace, "local"),
        .remote_dir =
            kasumi::test::workspace_path(workspace, "remote").string(),
        .min_history_depth = kasumi::history::maximum_graph_depth + 1,
        .min_history_age_hours = 6};

    const auto result =
        kasumi::application::create_profile(environment, invalid, key());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::ProfileErrorCode::ConfigFailure);
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/config.toml")));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles/demo")));
}

TEST(ApplicationProfileTest,
     UpdateRenameAndDeleteKeepConfigAndStorageCoherent) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-profile-lifecycle");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    Profile profile{
        "old",
        kasumi::test::workspace_path(workspace, "local old"),
        kasumi::test::workspace_path(workspace, "remote old").string()};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    profile.local_dir = kasumi::test::workspace_path(workspace, "local new");
    profile.remote_dir =
        kasumi::test::workspace_path(workspace, "remote new").string();
    ASSERT_TRUE(kasumi::application::update_profile(environment, profile));
    ASSERT_TRUE(kasumi::application::rename_profile(environment, "old", "new"));
    EXPECT_TRUE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles/new")));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles/old")));

    const auto collision =
        kasumi::application::rename_profile(environment, "new", "new");
    EXPECT_FALSE(collision.has_value());
    ASSERT_TRUE(kasumi::application::delete_profile(environment, "new"));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles/new")));
    EXPECT_TRUE(kasumi::application::list_profiles(environment)->empty());
}

TEST(ApplicationProfileTest,
     PasswordPairCreatesUsableVaultWithoutExposingSecrets) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-password-profile");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    ProfileCredentials credentials =
        kasumi::application::PasswordPair{"test password", "test salt secret"};
    const Profile profile{
        "password",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, std::move(credentials)));
    EXPECT_TRUE(std::filesystem::exists(kasumi::test::workspace_path(
        workspace, "app/profiles/password/key.bin")));
}


TEST(ApplicationProfileTest, CloneRejectsNonexistentSource) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-no-source");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    auto res = kasumi::application::clone_profile(
        environment, "nonexistent", "destination");
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, kasumi::application::ProfileErrorCode::NotFound);
}

TEST(ApplicationProfileTest, CloneRejectsDuplicateDestination) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-dup-dest");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const Profile profile{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    auto res = kasumi::application::clone_profile(
        environment, "source", "source");
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code,
              kasumi::application::ProfileErrorCode::AlreadyExists);
}

TEST(ApplicationProfileTest, CloneRejectsOccupiedPrivateDirectory) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-occupied");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const Profile profile{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    const auto dest_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(dest_paths.has_value());
    std::filesystem::create_directories(dest_paths->profile_dir);

    auto res = kasumi::application::clone_profile(
        environment, "source", "destination");
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code,
              kasumi::application::ProfileErrorCode::StorageFailure);
}

TEST(ApplicationProfileTest,
     CloneCopiesConfigurationAndKeyWithoutInheritingState) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-copy");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const Profile profile{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root",
        7,
        12};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    const auto src_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "source");
    ASSERT_TRUE(src_paths.has_value());
    ASSERT_TRUE(save_height(src_paths->database_path, 1));
    const auto source_key =
        kasumi::runtime::vault::read_only(src_paths->key_path);
    ASSERT_TRUE(source_key.has_value());
    const auto source_journal =
        kasumi::application::sync::journal::create_record(
            0, 0, kasumi::make_sync_plan({}, 0));
    ASSERT_TRUE(source_journal.has_value());
    const auto source_journal_paths =
        kasumi::application::sync::journal::make_paths(src_paths->profile_dir);
    ASSERT_TRUE(source_journal_paths.has_value());
    ASSERT_TRUE(kasumi::application::sync::journal::save(
        *source_journal_paths, *source_journal, *source_key));

    auto res = kasumi::application::clone_profile(
        environment, "source", "destination");
    ASSERT_TRUE(res.has_value()) << res.error().detail;

    auto profiles_res = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(profiles_res.has_value());
    auto it = std::ranges::find_if(*profiles_res, [](const auto& p) {
        return p.name == "destination";
    });
    ASSERT_NE(it, profiles_res->end());
    EXPECT_EQ(it->local_dir, profile.local_dir);
    EXPECT_EQ(it->remote_dir, profile.remote_dir);
    EXPECT_EQ(it->min_history_depth, 7U);
    EXPECT_EQ(it->min_history_age_hours, 12U);

    const auto dest_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(dest_paths.has_value());

    const auto source_state =
        kasumi::state_storage::load_state(src_paths->database_path);
    ASSERT_TRUE(source_state.has_value());
    ASSERT_TRUE(source_state->has_value());
    EXPECT_EQ(source_state->value().height, 1U);
    const auto destination_state =
        kasumi::state_storage::load_state(dest_paths->database_path);
    ASSERT_TRUE(destination_state.has_value());
    EXPECT_FALSE(destination_state->has_value());

    auto src_key = kasumi::runtime::vault::read_only(src_paths->key_path);
    auto dest_key = kasumi::runtime::vault::read_only(dest_paths->key_path);
    ASSERT_TRUE(src_key.has_value());
    ASSERT_TRUE(dest_key.has_value());
    EXPECT_EQ(*src_key, *dest_key);
    const auto destination_journal =
        kasumi::application::sync::journal::make_paths(dest_paths->profile_dir);
    ASSERT_TRUE(destination_journal.has_value());
    EXPECT_EQ(kasumi::application::sync::journal::inspect(
                  *destination_journal, *dest_key),
              kasumi::application::sync::journal::InspectionResult::Absent);
}

TEST(ApplicationProfileTest, CloneInitializesIndependentDatabaseSchema) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-schema");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const Profile profile{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    ASSERT_TRUE(
        kasumi::application::clone_profile(environment, "source", "destination"));

    const auto dest_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(dest_paths.has_value());
    EXPECT_TRUE(
        kasumi::state_storage::validate(dest_paths->database_path));
}

TEST(ApplicationProfileTest, CloneRollbackPreservesSubstitutedKey) {
    expect_clone_rollback_preserves_substituted_file(
        "app-profile-clone-key-substitute",
        "key.bin",
        "replacement key owned by another process");
}

TEST(ApplicationProfileTest, CloneRollbackPreservesSubstitutedDatabase) {
    expect_clone_rollback_preserves_substituted_file(
        "app-profile-clone-db-substitute",
        "db.sqlite",
        "replacement database owned by another process");
}

TEST(ApplicationProfileTest,
     CloneRollbackPreservesUnownedOrSubstitutedSqliteSidecar) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-wal-substitute");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile source{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, source, key()));
    const auto destination = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(destination.has_value());
    const auto wal_path = std::filesystem::path{
        destination->database_path.string() + "-wal"};
    const auto staged_path =
        kasumi::test::workspace_path(workspace, "replacement-wal");
    constexpr std::string_view contents = "foreign WAL sidecar";

    TestDirectoryIdentity directory_identity;
    kasumi::platform::private_storage::FileIdentity sidecar_identity;
    FileReplacementEvidence replacement;
    bool sidecar_preexisted = false;
    bool sidecar_installed = false;
    {
        kasumi::application::fault_test::ScopedCloneFaultInjection fault(
            kasumi::application::fault_test::CloneFaultStage::FailConfigSave,
            [&](kasumi::application::fault_test::CloneFaultStage) {
                directory_identity =
                    test_directory_identity(destination->profile_dir);
                sidecar_preexisted =
                    kasumi::platform::private_storage::query_file_identity(
                        wal_path).valid;
                if (sidecar_preexisted) {
                    replacement = replace_file(
                        wal_path, staged_path, contents);
                    sidecar_identity = replacement.replacement;
                    sidecar_installed = replacement.completed;
                } else {
                    sidecar_installed = install_file(
                        wal_path, staged_path, contents);
                    sidecar_identity =
                        kasumi::platform::private_storage::query_file_identity(
                            wal_path);
                }
            });
        const auto result = kasumi::application::clone_profile(
            environment, "source", "destination");
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code,
                  kasumi::application::ProfileErrorCode::ConfigFailure);
        EXPECT_NE(result.error().detail.find("rollback also failed"),
                  std::string::npos);
    }

    EXPECT_TRUE(sidecar_installed);
    ASSERT_TRUE(directory_identity.valid);
    ASSERT_TRUE(sidecar_identity.valid);
    if (sidecar_preexisted) {
        EXPECT_TRUE(replacement.original.valid);
        EXPECT_NE(replacement.original, replacement.replacement);
    }
    EXPECT_EQ(test_directory_identity(destination->profile_dir),
              directory_identity);
    EXPECT_EQ(kasumi::platform::private_storage::query_file_identity(wal_path),
              sidecar_identity);
    std::ifstream stream(wal_path, std::ios::binary);
    const std::string actual{std::istreambuf_iterator<char>(stream),
                             std::istreambuf_iterator<char>()};
    EXPECT_EQ(actual, contents);
}

TEST(ApplicationProfileTest,
     CloneRollbackAcceptsSqliteSidecarsRemovedBeforeRollback) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-sqlite-sidecars");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile source{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, source, key()));
    const auto destination = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(destination.has_value());
    const auto wal_path =
        std::filesystem::path{destination->database_path.string() + "-wal"};
    const auto shm_path =
        std::filesystem::path{destination->database_path.string() + "-shm"};

    bool sidecars_created = false;
    bool sidecars_removed = false;
    {
        kasumi::application::fault_test::ScopedCloneFaultInjection fault(
            kasumi::application::fault_test::CloneFaultStage::FailConfigSave,
            [&](kasumi::application::fault_test::CloneFaultStage) {
                auto database = kasumi::sqlite::open(
                    destination->database_path, SQLITE_OPEN_READWRITE);
                if (!database ||
                    !kasumi::sqlite::execute(database->get(), "BEGIN IMMEDIATE") ||
                    !kasumi::sqlite::execute(
                        database->get(),
                        "INSERT INTO metadata(key, value) "
                        "VALUES ('rollback_probe', '1')")) {
                    return;
                }
                sidecars_created = std::filesystem::exists(wal_path) &&
                                   std::filesystem::exists(shm_path);
                static_cast<void>(kasumi::sqlite::execute(
                    database->get(), "ROLLBACK"));
                database->reset();
                sidecars_removed = !std::filesystem::exists(wal_path) &&
                                   !std::filesystem::exists(shm_path);
            });
        const auto result = kasumi::application::clone_profile(
            environment, "source", "destination");
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code,
                  kasumi::application::ProfileErrorCode::ConfigFailure);
        EXPECT_EQ(result.error().detail.find("rollback also failed"),
                  std::string::npos);
    }

    EXPECT_TRUE(sidecars_created);
    EXPECT_TRUE(sidecars_removed);
    EXPECT_FALSE(std::filesystem::exists(destination->profile_dir));
}

TEST(ApplicationProfileTest,
     CloneRollbackPreservesUnknownFileInsertedAfterInitialization) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-unknown-entry");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile source{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, source, key()));
    const auto destination = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(destination.has_value());
    const auto unknown_path = destination->profile_dir / "unrecognized.bin";
    const auto staged_path =
        kasumi::test::workspace_path(workspace, "unknown-entry.bin");
    constexpr std::string_view contents = "unowned profile data";

    TestDirectoryIdentity directory_identity;
    kasumi::platform::private_storage::FileIdentity unknown_identity;
    bool installed = false;
    {
        kasumi::application::fault_test::ScopedCloneFaultInjection fault(
            kasumi::application::fault_test::CloneFaultStage::FailConfigSave,
            [&](kasumi::application::fault_test::CloneFaultStage) {
                directory_identity =
                    test_directory_identity(destination->profile_dir);
                installed = install_file(unknown_path, staged_path, contents);
                unknown_identity =
                    kasumi::platform::private_storage::query_file_identity(
                        unknown_path);
            });
        const auto result = kasumi::application::clone_profile(
            environment, "source", "destination");
        ASSERT_FALSE(result.has_value());
        EXPECT_NE(result.error().detail.find("rollback also failed"),
                  std::string::npos);
        EXPECT_NE(result.error().detail.find("unknown data"),
                  std::string::npos);
    }

    EXPECT_TRUE(installed);
    ASSERT_TRUE(directory_identity.valid);
    ASSERT_TRUE(unknown_identity.valid);
    EXPECT_EQ(test_directory_identity(destination->profile_dir),
              directory_identity);
    EXPECT_EQ(kasumi::platform::private_storage::query_file_identity(
                  unknown_path),
              unknown_identity);
    std::ifstream stream(unknown_path, std::ios::binary);
    const std::string actual{std::istreambuf_iterator<char>(stream),
                             std::istreambuf_iterator<char>()};
    EXPECT_EQ(actual, contents);
}

TEST(ApplicationProfileTest,
     CloneRollbackPreservesSymlinkSubstitutedKeyAndTarget) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-symlink-key");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile source{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, source, key()));
    const auto destination = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(destination.has_value());
    const auto target = kasumi::test::workspace_path(workspace, "outside.txt");
    constexpr std::string_view contents = "outside data must survive";
    {
        std::ofstream stream(target, std::ios::binary);
        stream << contents;
        ASSERT_TRUE(stream.good());
    }

    kasumi::platform::private_storage::FileIdentity original_identity;
    TestDirectoryIdentity directory_identity;
    std::error_code error;
    {
        kasumi::application::fault_test::ScopedCloneFaultInjection fault(
            kasumi::application::fault_test::CloneFaultStage::FailConfigSave,
            [&](kasumi::application::fault_test::CloneFaultStage) {
                directory_identity =
                    test_directory_identity(destination->profile_dir);
                original_identity =
                    kasumi::platform::private_storage::query_file_identity(
                        destination->key_path);
                std::filesystem::remove(destination->key_path, error);
                if (!error) {
                    std::filesystem::create_symlink(
                        target, destination->key_path, error);
                }
            });
        const auto result = kasumi::application::clone_profile(
            environment, "source", "destination");
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code,
                  kasumi::application::ProfileErrorCode::ConfigFailure);
        if (!error) {
            EXPECT_NE(result.error().detail.find("rollback also failed"),
                      std::string::npos);
        }
    }

    if (error) {
        GTEST_SKIP() << "file symlinks unavailable: " << error.message();
    }
    ASSERT_TRUE(original_identity.valid);
    ASSERT_TRUE(directory_identity.valid);
    EXPECT_TRUE(std::filesystem::is_symlink(
        std::filesystem::symlink_status(destination->key_path)));
    EXPECT_FALSE(kasumi::platform::private_storage::query_file_identity(
                     destination->key_path)
                     .valid);
    EXPECT_EQ(test_directory_identity(destination->profile_dir),
              directory_identity);
    std::ifstream stream(target, std::ios::binary);
    const std::string actual{std::istreambuf_iterator<char>(stream),
                             std::istreambuf_iterator<char>()};
    EXPECT_EQ(actual, contents);
}

#if defined(_WIN32)
TEST(ApplicationProfileTest,
     CloneRollbackPreservesJunctionSubstitutedDestination) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-junction");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile source{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, source, key()));
    const auto destination = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(destination.has_value());
    const auto moved =
        kasumi::test::workspace_path(workspace, "moved-destination");
    const auto outside =
        kasumi::test::workspace_path(workspace, "outside-directory");
    const auto important = outside / "important.txt";
    constexpr std::string_view contents = "junction target data";
    std::filesystem::create_directories(outside);
    {
        std::ofstream stream(important, std::ios::binary);
        stream << contents;
        ASSERT_TRUE(stream.good());
    }

    bool fault_reached = false;
    bool directory_moved = false;
    bool junction_created = false;
    std::error_code move_error;
    std::error_code junction_error;
    {
        kasumi::application::fault_test::ScopedCloneFaultInjection fault(
            kasumi::application::fault_test::CloneFaultStage::FailDatabaseInit,
            [&](kasumi::application::fault_test::CloneFaultStage) {
                fault_reached = true;
                std::filesystem::rename(
                    destination->profile_dir, moved, move_error);
                directory_moved = !move_error;
                if (directory_moved) {
                    junction_created = create_directory_junction(
                        destination->profile_dir, outside, junction_error);
                }
            });
        const auto result = kasumi::application::clone_profile(
            environment, "source", "destination");
        ASSERT_FALSE(result.has_value());
        if (junction_created) {
            EXPECT_NE(result.error().detail.find("rollback also failed"),
                      std::string::npos);
        }
    }

    ASSERT_TRUE(fault_reached);
    ASSERT_TRUE(directory_moved) << move_error.message();
    if (!junction_created) {
        GTEST_SKIP() << "directory junction unavailable: "
                     << junction_error.message();
    }
    const auto attributes = GetFileAttributesW(destination->profile_dir.c_str());
    ASSERT_NE(attributes, INVALID_FILE_ATTRIBUTES);
    EXPECT_NE(attributes & FILE_ATTRIBUTE_REPARSE_POINT, 0U);
    EXPECT_TRUE(std::filesystem::exists(important));
    std::ifstream stream(important, std::ios::binary);
    const std::string actual{std::istreambuf_iterator<char>(stream),
                             std::istreambuf_iterator<char>()};
    EXPECT_EQ(actual, contents);
}
#endif

TEST(ApplicationProfileTest,
     CloneRollbackPreservesSubstitutedDestination) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-substitute");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile source{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, source, key()));

    const auto destination = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(destination.has_value());
    const auto moved =
        kasumi::test::workspace_path(workspace, "moved-destination");
    const auto important = destination->profile_dir / "important.txt";
    constexpr std::string_view contents = "preserve substituted data";
    bool fault_reached = false;
    bool replacement_created = false;
    std::error_code error;
    {
        kasumi::application::fault_test::ScopedCloneFaultInjection fault(
            kasumi::application::fault_test::CloneFaultStage::FailDatabaseInit,
            [&](kasumi::application::fault_test::CloneFaultStage) {
                fault_reached = true;
                std::filesystem::rename(destination->profile_dir, moved, error);
                if (error) {
                    return;
                }
                std::filesystem::create_directory(destination->profile_dir,
                                                  error);
                if (error) {
                    return;
                }
                std::ofstream stream(important, std::ios::binary);
                stream << contents;
                replacement_created = static_cast<bool>(stream);
            });
        const auto result = kasumi::application::clone_profile(
            environment, "source", "destination");
        ASSERT_FALSE(result.has_value());
        EXPECT_NE(result.error().detail.find("rollback also failed"),
                  std::string::npos);
    }

    EXPECT_TRUE(fault_reached);
    ASSERT_TRUE(replacement_created);
    ASSERT_TRUE(std::filesystem::exists(important));
    std::ifstream stream(important, std::ios::binary);
    const std::string actual{std::istreambuf_iterator<char>(stream),
                             std::istreambuf_iterator<char>()};
    EXPECT_EQ(actual, contents);
}

TEST(ApplicationProfileTest, CloneRollbackOnKeyWriteFailure) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-rb-key");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const Profile profile{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    const auto dest_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(dest_paths.has_value());

    bool reached_stage = false;
    bool profile_dir_existed = false;
    bool key_not_yet_created = false;

    {
        kasumi::application::fault_test::ScopedCloneFaultInjection fault(
            kasumi::application::fault_test::CloneFaultStage::FailKeyWrite,
            [&](kasumi::application::fault_test::CloneFaultStage) {
                reached_stage = true;
                profile_dir_existed =
                    std::filesystem::exists(dest_paths->profile_dir);
                key_not_yet_created =
                    !std::filesystem::exists(dest_paths->key_path);
            });

        auto res = kasumi::application::clone_profile(
            environment, "source", "destination");
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code,
                  kasumi::application::ProfileErrorCode::StorageFailure);
    }

    EXPECT_TRUE(reached_stage);
    EXPECT_TRUE(profile_dir_existed);
    EXPECT_TRUE(key_not_yet_created);

    // Rollback must have removed the newly created destination profile directory
    EXPECT_FALSE(std::filesystem::exists(dest_paths->profile_dir));

    // Source profile must remain intact
    const auto src_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "source");
    ASSERT_TRUE(src_paths.has_value());
    EXPECT_TRUE(std::filesystem::exists(src_paths->profile_dir));
    EXPECT_TRUE(std::filesystem::exists(src_paths->key_path));
    EXPECT_TRUE(std::filesystem::exists(src_paths->database_path));
}

TEST(ApplicationProfileTest, CloneRollbackOnDatabaseInitFailure) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-rb-db");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const Profile profile{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    const auto dest_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(dest_paths.has_value());

    bool reached_stage = false;
    bool profile_dir_existed = false;
    bool key_existed = false;

    {
        kasumi::application::fault_test::ScopedCloneFaultInjection fault(
            kasumi::application::fault_test::CloneFaultStage::FailDatabaseInit,
            [&](kasumi::application::fault_test::CloneFaultStage) {
                reached_stage = true;
                profile_dir_existed =
                    std::filesystem::exists(dest_paths->profile_dir);
                key_existed = std::filesystem::exists(dest_paths->key_path);
            });

        auto res = kasumi::application::clone_profile(
            environment, "source", "destination");
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code,
                  kasumi::application::ProfileErrorCode::StorageFailure);
    }

    EXPECT_TRUE(reached_stage);
    EXPECT_TRUE(profile_dir_existed);
    EXPECT_TRUE(key_existed);

    // Rollback must have removed the destination directory and its key
    EXPECT_FALSE(std::filesystem::exists(dest_paths->profile_dir));
    EXPECT_FALSE(std::filesystem::exists(dest_paths->key_path));

    // Source profile must remain intact
    const auto src_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "source");
    ASSERT_TRUE(src_paths.has_value());
    EXPECT_TRUE(std::filesystem::exists(src_paths->profile_dir));
    EXPECT_TRUE(std::filesystem::exists(src_paths->key_path));
    EXPECT_TRUE(std::filesystem::exists(src_paths->database_path));
}

TEST(ApplicationProfileTest, CloneRollbackOnConfigSaveFailure) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-rb-cfg");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const Profile profile{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    const auto dest_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(dest_paths.has_value());

    bool reached_stage = false;
    bool profile_dir_existed = false;
    bool key_existed = false;
    bool db_existed = false;

    {
        kasumi::application::fault_test::ScopedCloneFaultInjection fault(
            kasumi::application::fault_test::CloneFaultStage::FailConfigSave,
            [&](kasumi::application::fault_test::CloneFaultStage) {
                reached_stage = true;
                profile_dir_existed =
                    std::filesystem::exists(dest_paths->profile_dir);
                key_existed = std::filesystem::exists(dest_paths->key_path);
                db_existed =
                    std::filesystem::exists(dest_paths->database_path);
            });

        auto res = kasumi::application::clone_profile(
            environment, "source", "destination");
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code,
                  kasumi::application::ProfileErrorCode::ConfigFailure);
    }

    EXPECT_TRUE(reached_stage);
    EXPECT_TRUE(profile_dir_existed);
    EXPECT_TRUE(key_existed);
    EXPECT_TRUE(db_existed);

    // Rollback must have removed destination resources
    EXPECT_FALSE(std::filesystem::exists(dest_paths->profile_dir));

    // Config.toml must NOT contain destination
    auto profiles_res = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(profiles_res.has_value());
    EXPECT_EQ(profiles_res->size(), 1U);
    EXPECT_EQ((*profiles_res)[0].name, "source");

    // Source profile must remain intact
    const auto src_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "source");
    ASSERT_TRUE(src_paths.has_value());
    EXPECT_TRUE(std::filesystem::exists(src_paths->profile_dir));
    EXPECT_TRUE(std::filesystem::exists(src_paths->key_path));
    EXPECT_TRUE(std::filesystem::exists(src_paths->database_path));
}

TEST(ApplicationProfileTest, CloneRollbackFailureReportsBothErrors) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-rb-fail");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const Profile profile{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    bool fault_hit = false;
    {
        kasumi::application::fault_test::ScopedCloneFaultInjection fault(
            kasumi::application::fault_test::CloneFaultStage::FailRollbackRemove,
            [&](kasumi::application::fault_test::CloneFaultStage) {
                fault_hit = true;
            });

        auto res = kasumi::application::clone_profile(
            environment, "source", "destination");
        ASSERT_FALSE(res.has_value());
        EXPECT_NE(res.error().detail.find("rollback also failed"),
                  std::string::npos);
        EXPECT_NE(
            res.error().detail.find("injected rollback deletion failure"),
            std::string::npos);
    }

    EXPECT_TRUE(fault_hit);
}

TEST(ApplicationProfileTest, CloneRetryAfterPartialFailureSucceeds) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-retry");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const Profile profile{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    const auto dest_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "destination");
    ASSERT_TRUE(dest_paths.has_value());

    bool first_attempt_failed_at_db = false;
    {
        kasumi::application::fault_test::ScopedCloneFaultInjection fault(
            kasumi::application::fault_test::CloneFaultStage::FailDatabaseInit,
            [&](kasumi::application::fault_test::CloneFaultStage) {
                first_attempt_failed_at_db = true;
            });

        auto fail_res = kasumi::application::clone_profile(
            environment, "source", "destination");
        ASSERT_FALSE(fail_res.has_value());
    }

    EXPECT_TRUE(first_attempt_failed_at_db);
    EXPECT_FALSE(std::filesystem::exists(dest_paths->profile_dir));

    // Retry without fault injection must succeed completely
    auto retry_res = kasumi::application::clone_profile(
        environment, "source", "destination");
    ASSERT_TRUE(retry_res.has_value()) << retry_res.error().detail;

    EXPECT_TRUE(std::filesystem::exists(dest_paths->profile_dir));
    EXPECT_TRUE(std::filesystem::exists(dest_paths->key_path));
    EXPECT_TRUE(std::filesystem::exists(dest_paths->database_path));
    EXPECT_TRUE(kasumi::state_storage::validate(dest_paths->database_path));

    auto profiles_res = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(profiles_res.has_value());
    EXPECT_EQ(profiles_res->size(), 2U);
}

TEST(ApplicationProfileTest, CloneSourceRemainsIntactOnFailure) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-src-intact");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const Profile profile{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    const auto src_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "source");
    ASSERT_TRUE(src_paths.has_value());
    const auto key_before =
        kasumi::runtime::vault::read_only(src_paths->key_path);
    ASSERT_TRUE(key_before.has_value());

    auto fail_res = kasumi::application::clone_profile(
        environment, "source", "invalid name with spaces");
    ASSERT_FALSE(fail_res.has_value());

    const auto key_after =
        kasumi::runtime::vault::read_only(src_paths->key_path);
    ASSERT_TRUE(key_after.has_value());
    EXPECT_EQ(*key_before, *key_after);
}

TEST(ApplicationProfileTest, ClonePreservesOtherProfilesResources) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-clone-preserves");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const Profile profile1{
        "source",
        kasumi::test::workspace_path(workspace, "local1"),
        "remote:root1"};
    const Profile profile2{
        "other",
        kasumi::test::workspace_path(workspace, "local2"),
        "remote:root2"};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile1, key()));
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile2, key()));

    const auto other_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "other");
    ASSERT_TRUE(other_paths.has_value());

    {
        kasumi::application::fault_test::ScopedCloneFaultInjection fault(
            kasumi::application::fault_test::CloneFaultStage::FailKeyWrite);
        auto fail_res = kasumi::application::clone_profile(
            environment, "source", "target");
        ASSERT_FALSE(fail_res.has_value());
    }

    EXPECT_TRUE(std::filesystem::exists(other_paths->profile_dir));
    EXPECT_TRUE(std::filesystem::exists(other_paths->key_path));
    EXPECT_TRUE(std::filesystem::exists(other_paths->database_path));
    EXPECT_TRUE(
        kasumi::state_storage::validate(other_paths->database_path));
}

TEST(ApplicationProfileTest,
     ConfigOperationsSerializeAcrossThreadsWithoutUpdateLoss) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-concurrency");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const Profile base_profile{
        "base",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, base_profile, key()));

    constexpr std::size_t num_clones = 6;
    std::vector<std::jthread> threads;
    std::vector<std::expected<void, kasumi::application::ProfileError>> results(
        num_clones);

    for (std::size_t i = 0; i < num_clones; ++i) {
        threads.emplace_back([&, i] {
            std::string dest_name = "clone_" + std::to_string(i);
            results[i] = kasumi::application::clone_profile(
                environment, "base", dest_name);
        });
    }

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    for (std::size_t i = 0; i < num_clones; ++i) {
        EXPECT_TRUE(results[i].has_value())
            << "Clone " << i << " failed: " << results[i].error().detail;
    }

    auto profiles_res = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(profiles_res.has_value());
    EXPECT_EQ(profiles_res->size(), num_clones + 1);
}

TEST(ApplicationProfileTest, ConfigOperationFailsWhenLockAcquisitionFails) {
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-lock-fail");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const Profile profile{
        "source",
        kasumi::test::workspace_path(workspace, "local"),
        "remote:root"};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    auto lock_path = environment.app_data_dir / "config.lock";
    auto held_lock = kasumi::platform::acquire_profile_lock(lock_path);
    ASSERT_TRUE(held_lock.has_value());

    auto res = kasumi::application::clone_profile(
        environment, "source", "target");

    kasumi::platform::release_profile_lock(*held_lock);

    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code,
              kasumi::application::ProfileErrorCode::LockFailure);
}

} // namespace
