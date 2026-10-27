#include "application/profile.hpp"
#include "application/sync/journal.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "runtime/paths.hpp"
#include "runtime/profile.hpp"
#include "state_storage/database_connection.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sqlite3.h>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "application/profile_fault_test.hpp"
#include "platform/profile_lock.hpp"
#include "runtime/vault.hpp"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <aclapi.h>
#include <sddl.h>
#include <windows.h>
#include <winioctl.h>
#else
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
extern char** environ;
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
                 std::uint64_t height,
                 bool pending = false) {
    kasumi::Snapshot tree{{
        {.path = "", .is_directory = true},
        {.path = "file-" + std::to_string(height) + ".txt",
         .hash = kasumi::hasher::hash_string("sample_content"),
         .size = height * 100,
         .mtime = static_cast<std::int64_t>(height * 200),
         .is_directory = false},
    }};
    kasumi::finalize_snapshot(tree);
    kasumi::state_storage::StoredState state{
        .tree = std::move(tree),
        .height = height,
        .commit_id =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    };
    if (pending) {
        state.pending_materializations.push_back(state.tree.rows[1]);
    }
    return kasumi::state_storage::save_state(database_path, state);
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


struct FileSnapshot {
    std::filesystem::file_type type = std::filesystem::file_type::none;
    std::uintmax_t size = 0;
    std::array<std::byte, 32> sha256{};
    std::int64_t mtime = 0;
    std::int64_t change_time = 0;
    std::array<std::byte, 32> security{};
    bool operator==(const FileSnapshot&) const = default;
};

#if defined(_WIN32)
std::int64_t windows_basic_time(const std::filesystem::path& path, bool change) {
    HANDLE handle = CreateFileW(path.c_str(),
                                FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE |
                                    FILE_SHARE_DELETE,
                                nullptr,
                                OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS |
                                    FILE_FLAG_OPEN_REPARSE_POINT,
                                nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return 0;
    }
    FILE_BASIC_INFO info{};
    const BOOL ok = GetFileInformationByHandleEx(
        handle, FileBasicInfo, &info, sizeof(info));
    CloseHandle(handle);
    if (!ok) {
        return 0;
    }
    return change ? info.ChangeTime.QuadPart : info.LastWriteTime.QuadPart;
}

std::array<std::byte, 32>
windows_security_hash(const std::filesystem::path& path) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL dacl = nullptr;
    if (GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()),
                              SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION,
                              nullptr,
                              nullptr,
                              &dacl,
                              nullptr,
                              &descriptor) != ERROR_SUCCESS) {
        return {};
    }
    std::array<std::byte, 32> hash{};
    if (dacl != nullptr) {
        hash = kasumi::hasher::hash_bytes(dacl, dacl->AclSize);
    }
    if (descriptor != nullptr) {
        LocalFree(descriptor);
    }
    return hash;
}
#else
#include <sys/stat.h>
#include <unistd.h>

std::int64_t posix_time_ns(const timespec& value) {
    return static_cast<std::int64_t>(value.tv_sec) * 1'000'000'000LL +
           static_cast<std::int64_t>(value.tv_nsec);
}
#endif

FileSnapshot capture_path(const std::filesystem::path& path) {
    FileSnapshot snapshot;
    std::error_code ec;
    snapshot.type = std::filesystem::symlink_status(path, ec).type();
    if (ec) {
        return snapshot;
    }
    if (snapshot.type == std::filesystem::file_type::regular) {
        snapshot.size = std::filesystem::file_size(path, ec);
        if (ec) {
            return snapshot;
        }
        std::vector<std::byte> bytes(static_cast<std::size_t>(snapshot.size));
        if (!bytes.empty()) {
            std::ifstream stream(path, std::ios::binary);
            stream.read(reinterpret_cast<char*>(bytes.data()),
                        static_cast<std::streamsize>(bytes.size()));
        }
        snapshot.sha256 = kasumi::hasher::hash_bytes(bytes.data(), bytes.size());
    }
#if defined(_WIN32)
    snapshot.mtime = windows_basic_time(path, false);
    snapshot.change_time = windows_basic_time(path, true);
    snapshot.security = windows_security_hash(path);
#else
    struct stat status {};
    if (::lstat(path.c_str(), &status) == 0) {
        snapshot.mtime = posix_time_ns(status.st_mtim);
        snapshot.change_time = posix_time_ns(status.st_ctim);
        snapshot.security = kasumi::hasher::hash_bytes(
            &status.st_mode, sizeof(status.st_mode));
    }
#endif
    return snapshot;
}

std::map<std::string, FileSnapshot>
capture_directory_snapshot(const std::filesystem::path& dir) {
    std::map<std::string, FileSnapshot> result;
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) {
        return result;
    }
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(dir)) {
        auto relative = std::filesystem::relative(entry.path(), dir).string();
        std::ranges::replace(relative, '\\', '/');
        result[relative] = capture_path(entry.path());
    }
    return result;
}

bool grant_everyone_read(const std::filesystem::path& path) {
#if defined(_WIN32)
    PSID everyone = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-1-0", &everyone)) {
        return false;
    }
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    PACL original = nullptr;
    if (GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()),
                              SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION,
                              nullptr,
                              nullptr,
                              &original,
                              nullptr,
                              &descriptor) != ERROR_SUCCESS) {
        LocalFree(everyone);
        return false;
    }
    EXPLICIT_ACCESSW access{};
    access.grfAccessPermissions = GENERIC_READ;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    access.Trustee.ptstrName = static_cast<LPWSTR>(everyone);
    PACL updated = nullptr;
    const DWORD built = SetEntriesInAclW(1, &access, original, &updated);
    const bool applied =
        built == ERROR_SUCCESS &&
        SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()),
                              SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION |
                                  PROTECTED_DACL_SECURITY_INFORMATION,
                              nullptr,
                              nullptr,
                              updated,
                              nullptr) == ERROR_SUCCESS;
    if (updated != nullptr) {
        LocalFree(updated);
    }
    if (descriptor != nullptr) {
        LocalFree(descriptor);
    }
    LocalFree(everyone);
    return applied;
#else
    return ::chmod(path.c_str(), 0640) == 0;
#endif
}

class ScopedDeniedRead {
public:
    explicit ScopedDeniedRead(std::filesystem::path path)
        : path_(std::move(path)) {
        deny();
    }

    ~ScopedDeniedRead() {
        static_cast<void>(restore());
    }

    ScopedDeniedRead(const ScopedDeniedRead&) = delete;
    ScopedDeniedRead& operator=(const ScopedDeniedRead&) = delete;

    bool active() const noexcept {
        return active_;
    }

    bool restore() {
        if (!active_) {
            return true;
        }
#if defined(_WIN32)
        const bool restored =
            SetNamedSecurityInfoW(const_cast<wchar_t*>(path_.c_str()),
                                  SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION |
                                      PROTECTED_DACL_SECURITY_INFORMATION,
                                  nullptr,
                                  nullptr,
                                  original_dacl_,
                                  nullptr) == ERROR_SUCCESS;
        if (restored) {
            active_ = false;
            if (original_descriptor_ != nullptr) {
                LocalFree(original_descriptor_);
                original_descriptor_ = nullptr;
                original_dacl_ = nullptr;
            }
            if (sid_ != nullptr) {
                LocalFree(sid_);
                sid_ = nullptr;
            }
        }
        return restored;
#else
        if (have_mode_ && ::chmod(path_.c_str(), original_mode_) != 0) {
            return false;
        }
        active_ = false;
        return true;
#endif
    }

private:
    void deny() {
#if defined(_WIN32)
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            return;
        }
        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        std::vector<std::byte> token_user(size);
        const bool token_ok =
            size != 0 &&
            GetTokenInformation(
                token, TokenUser, token_user.data(), size, &size);
        CloseHandle(token);
        if (!token_ok) {
            return;
        }
        wchar_t* sid_text = nullptr;
        const auto* user =
            reinterpret_cast<const TOKEN_USER*>(token_user.data());
        if (!ConvertSidToStringSidW(user->User.Sid, &sid_text)) {
            return;
        }
        const std::wstring sid_string = sid_text;
        LocalFree(sid_text);
        if (!ConvertStringSidToSidW(sid_string.c_str(), &sid_)) {
            return;
        }
        if (GetNamedSecurityInfoW(const_cast<wchar_t*>(path_.c_str()),
                                  SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION,
                                  nullptr,
                                  nullptr,
                                  &original_dacl_,
                                  nullptr,
                                  &original_descriptor_) != ERROR_SUCCESS) {
            return;
        }
        EXPLICIT_ACCESSW access{};
        access.grfAccessPermissions = FILE_READ_DATA | FILE_READ_ATTRIBUTES |
                                      FILE_READ_EA | SYNCHRONIZE;
        access.grfAccessMode = DENY_ACCESS;
        access.grfInheritance = NO_INHERITANCE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_USER;
        access.Trustee.ptstrName = static_cast<LPWSTR>(sid_);
        PACL denied = nullptr;
        const DWORD built = SetEntriesInAclW(1, &access, original_dacl_, &denied);
        const bool applied =
            built == ERROR_SUCCESS &&
            SetNamedSecurityInfoW(const_cast<wchar_t*>(path_.c_str()),
                                  SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION |
                                      PROTECTED_DACL_SECURITY_INFORMATION,
                                  nullptr,
                                  nullptr,
                                  denied,
                                  nullptr) == ERROR_SUCCESS;
        if (denied != nullptr) {
            LocalFree(denied);
        }
        active_ = applied;
#else
        if (::geteuid() == 0) {
            return;
        }
        struct stat status {};
        if (::lstat(path_.c_str(), &status) != 0) {
            return;
        }
        original_mode_ = status.st_mode;
        have_mode_ = true;
        active_ = ::chmod(path_.c_str(), 0000) == 0;
#endif
    }

    std::filesystem::path path_;
    bool active_ = false;
#if defined(_WIN32)
    PSECURITY_DESCRIPTOR original_descriptor_ = nullptr;
    PACL original_dacl_ = nullptr;
    PSID sid_ = nullptr;
#else
    mode_t original_mode_ = 0;
    bool have_mode_ = false;
#endif
};

class ScopedTempRoot {
public:
    explicit ScopedTempRoot(const TempWorkspace& workspace) {
        root_ = kasumi::test::workspace_path(workspace, "inspect-temp");
        std::filesystem::create_directories(root_);
        old_tmp_ = environment_value("TMP");
        old_temp_ = environment_value("TEMP");
        old_tmpdir_ = environment_value("TMPDIR");
        set_environment_value("TMP", root_.string());
        set_environment_value("TEMP", root_.string());
        set_environment_value("TMPDIR", root_.string());
    }

    ~ScopedTempRoot() {
        restore_environment_value("TMP", old_tmp_);
        restore_environment_value("TEMP", old_temp_);
        restore_environment_value("TMPDIR", old_tmpdir_);
        std::error_code ec;
        std::filesystem::remove_all(root_, ec);
        if (ec) {
            ADD_FAILURE() << "could not clean inspection temp fixture: "
                          << ec.message();
            return;
        }
        if (std::filesystem::exists(root_, ec) || ec) {
            ADD_FAILURE() << "inspection temp fixture remains after cleanup";
        }
    }

    ScopedTempRoot(const ScopedTempRoot&) = delete;
    ScopedTempRoot& operator=(const ScopedTempRoot&) = delete;

    const std::filesystem::path& root() const noexcept {
        return root_;
    }

    std::set<std::filesystem::path> inspection_directories() const {
        std::set<std::filesystem::path> result;
        std::error_code ec;
        for (const auto& entry :
             std::filesystem::directory_iterator(root_, ec)) {
            if (entry.path().filename().string().starts_with("kasumi_insp_")) {
                result.insert(entry.path());
            }
        }
        return result;
    }

private:
    static std::optional<std::string> environment_value(const char* name) {
        const char* value = std::getenv(name);
        if (value == nullptr) {
            return std::nullopt;
        }
        return std::string{value};
    }

    static void set_environment_value(const char* name,
                                      const std::string& value) {
#if defined(_WIN32)
        _putenv_s(name, value.c_str());
#else
        ::setenv(name, value.c_str(), 1);
#endif
    }

    static void restore_environment_value(
        const char* name, const std::optional<std::string>& value) {
#if defined(_WIN32)
        _putenv_s(name, value ? value->c_str() : "");
#else
        if (value) {
            ::setenv(name, value->c_str(), 1);
        } else {
            ::unsetenv(name);
        }
#endif
    }

    std::filesystem::path root_;
    std::optional<std::string> old_tmp_;
    std::optional<std::string> old_temp_;
    std::optional<std::string> old_tmpdir_;
};

struct ProfileFixture {
    TempWorkspace workspace;
    ExecutionEnvironment environment;
    Profile profile;

    explicit ProfileFixture(std::string name)
        : workspace(kasumi::test::make_temp_workspace(std::move(name))),
          environment{kasumi::test::workspace_path(workspace, "app")},
          profile{"main",
                  kasumi::test::workspace_path(workspace, "local"),
                  "remote:root"} {
        EXPECT_TRUE(kasumi::application::create_profile(
            environment, profile, key()));
    }

    std::filesystem::path profile_dir() const {
        auto paths = kasumi::runtime::resolve_profile_paths(
            environment.app_data_dir, "main");
        EXPECT_TRUE(paths.has_value());
        return paths ? paths->profile_dir : std::filesystem::path{};
    }

    std::filesystem::path database_path() const {
        auto paths = kasumi::runtime::resolve_profile_paths(
            environment.app_data_dir, "main");
        EXPECT_TRUE(paths.has_value());
        return paths ? paths->database_path : std::filesystem::path{};
    }

    std::filesystem::path key_path() const {
        auto paths = kasumi::runtime::resolve_profile_paths(
            environment.app_data_dir, "main");
        EXPECT_TRUE(paths.has_value());
        return paths ? paths->key_path : std::filesystem::path{};
    }
};

bool remove_sidecars_after_checkpoint(const std::filesystem::path& db) {
    auto opened = kasumi::sqlite::open(db, SQLITE_OPEN_READWRITE);
    if (!opened) {
        return false;
    }
    if (!kasumi::sqlite::execute(opened->get(),
                                 "PRAGMA wal_checkpoint(TRUNCATE)")) {
        return false;
    }
    opened->reset();
    std::error_code ec;
    std::filesystem::remove(std::filesystem::path{db.string() + "-wal"}, ec);
    ec.clear();
    std::filesystem::remove(std::filesystem::path{db.string() + "-shm"}, ec);
    return !std::filesystem::exists(std::filesystem::path{db.string() + "-wal"}) &&
           !std::filesystem::exists(std::filesystem::path{db.string() + "-shm"});
}

struct WalReaderGuard {
    std::unique_ptr<sqlite3, int (*)(sqlite3*)> db;
    sqlite3_stmt* stmt{nullptr};

    static std::optional<WalReaderGuard>
    open_and_hold_reader(const std::filesystem::path& db_path) {
        auto opened = kasumi::sqlite::open(db_path, SQLITE_OPEN_READONLY);
        if (!opened) {
            return std::nullopt;
        }
        sqlite3* raw_db = opened->get();
        char* err = nullptr;
        if (sqlite3_exec(raw_db, "BEGIN", nullptr, nullptr, &err) != SQLITE_OK) {
            sqlite3_free(err);
            return std::nullopt;
        }
        sqlite3_stmt* statement = nullptr;
        if (sqlite3_prepare_v2(raw_db,
                               "SELECT count(*) FROM metadata",
                               -1,
                               &statement,
                               nullptr) != SQLITE_OK) {
            return std::nullopt;
        }
        if (sqlite3_step(statement) != SQLITE_ROW) {
            sqlite3_finalize(statement);
            return std::nullopt;
        }
        return WalReaderGuard{std::move(*opened), statement};
    }

    ~WalReaderGuard() {
        if (stmt != nullptr) {
            sqlite3_finalize(stmt);
        }
        if (db) {
            char* err = nullptr;
            sqlite3_exec(db.get(), "ROLLBACK", nullptr, nullptr, &err);
            sqlite3_free(err);
        }
    }

    WalReaderGuard(std::unique_ptr<sqlite3, int (*)(sqlite3*)> d,
                   sqlite3_stmt* s)
        : db(std::move(d)), stmt(s) {}
    WalReaderGuard(WalReaderGuard&& other) noexcept
        : db(std::move(other.db)), stmt(std::exchange(other.stmt, nullptr)) {}
    WalReaderGuard(const WalReaderGuard&) = delete;
    WalReaderGuard& operator=(const WalReaderGuard&) = delete;
};

struct InspectionWriterProcess {
#if defined(_WIN32)
    HANDLE handle = nullptr;
#else
    pid_t pid = -1;
#endif

    InspectionWriterProcess() = default;
    InspectionWriterProcess(const InspectionWriterProcess&) = delete;
    InspectionWriterProcess& operator=(const InspectionWriterProcess&) = delete;
    InspectionWriterProcess(InspectionWriterProcess&& other) noexcept {
#if defined(_WIN32)
        handle = std::exchange(other.handle, nullptr);
#else
        pid = std::exchange(other.pid, -1);
#endif
    }

    ~InspectionWriterProcess() {
#if defined(_WIN32)
        if (handle != nullptr) {
            if (WaitForSingleObject(handle, 0) == WAIT_TIMEOUT) {
                TerminateProcess(handle, 1);
                WaitForSingleObject(handle, 5000);
            }
            CloseHandle(handle);
        }
#else
        if (pid > 0) {
            kill(pid, SIGTERM);
            int status = 0;
            waitpid(pid, &status, 0);
        }
#endif
    }

    bool wait_for(const std::filesystem::path& path,
                  std::chrono::seconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            std::error_code error;
            if (std::filesystem::exists(path, error)) {
                return !error;
            }
            if (error || exited()) {
                return false;
            }
#if defined(_WIN32)
            Sleep(5);
#else
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
#endif
        }
        return false;
    }

    int wait_for_exit(std::chrono::seconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
#if defined(_WIN32)
            if (WaitForSingleObject(handle, 5) == WAIT_OBJECT_0) {
                DWORD code = 1;
                GetExitCodeProcess(handle, &code);
                CloseHandle(handle);
                handle = nullptr;
                return static_cast<int>(code);
            }
#else
            int status = 0;
            const auto result = waitpid(pid, &status, WNOHANG);
            if (result == pid) {
                pid = -1;
                return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
            }
            if (result < 0) {
                pid = -1;
                return 1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{5});
#endif
        }
        return 1;
    }

private:
    bool exited() {
#if defined(_WIN32)
        return handle == nullptr || WaitForSingleObject(handle, 0) == WAIT_OBJECT_0;
#else
        if (pid <= 0) return true;
        int status = 0;
        const auto result = waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            pid = -1;
            return true;
        }
        return result < 0;
#endif
    }
};

std::optional<InspectionWriterProcess>
launch_inspection_writer(std::string_view mode,
                         const std::filesystem::path& database,
                         const std::filesystem::path& ready,
                         const std::filesystem::path& trigger,
                         const std::filesystem::path& done,
                         const std::filesystem::path& release) {
    InspectionWriterProcess child;
#if defined(_WIN32)
    const std::filesystem::path executable{KASUMI_INSPECT_SNAPSHOT_CHILD_PATH};
    const auto quote = [](const std::filesystem::path& path) {
        return L"\"" + path.native() + L"\"";
    };
    const auto mode_wide = std::wstring(mode.begin(), mode.end());
    std::wstring command = quote(executable) + L" " + mode_wide + L" " +
                           quote(database) + L" " + quote(ready) + L" " +
                           quote(trigger) + L" " + quote(done) + L" " +
                           quote(release);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable.c_str(),
                        command.data(),
                        nullptr,
                        nullptr,
                        FALSE,
                        CREATE_NO_WINDOW,
                        nullptr,
                        nullptr,
                        &startup,
                        &process)) {
        return std::nullopt;
    }
    CloseHandle(process.hThread);
    child.handle = process.hProcess;
#else
    const auto executable =
        std::string{KASUMI_INSPECT_SNAPSHOT_CHILD_PATH};
    const std::array<std::string, 7> arguments{
        executable,
        std::string{mode},
        kasumi::platform::path::to_utf8(database),
        kasumi::platform::path::to_utf8(ready),
        kasumi::platform::path::to_utf8(trigger),
        kasumi::platform::path::to_utf8(done),
        kasumi::platform::path::to_utf8(release),
    };
    std::array<char*, 8> pointers{};
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        pointers[index] = const_cast<char*>(arguments[index].c_str());
    }
    pid_t pid = -1;
    if (posix_spawn(&pid,
                    executable.c_str(),
                    nullptr,
                    nullptr,
                    pointers.data(),
                    environ) != 0) {
        return std::nullopt;
    }
    child.pid = pid;
#endif
    return child;
}

bool create_signal(const std::filesystem::path& path) {
    std::ofstream stream(path, std::ios::binary);
    return static_cast<bool>(stream);
}

TEST(ApplicationProfileTest,
     InspectLocalStateInitializedDatabaseHasNoAcceptedState) {
    ProfileFixture fixture{"app-profile-state-init"};
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Initialized);
}

TEST(ApplicationProfileTest,
     InspectLocalStateReadyHasConsistentAcceptedState) {
    ProfileFixture fixture{"app-profile-state-ready"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Ready);
}

TEST(ApplicationProfileTest,
     InspectLocalStateReadyWithConfirmedTransactionsInWal) {
    ProfileFixture fixture{"app-profile-state-wal-ready"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    auto reader = WalReaderGuard::open_and_hold_reader(fixture.database_path());
    ASSERT_TRUE(reader.has_value());
    ASSERT_TRUE(save_height(fixture.database_path(), 2));

    const auto wal_path = fixture.profile_dir() / "db.sqlite-wal";
    ASSERT_TRUE(std::filesystem::exists(wal_path));
    std::error_code ec;
    ASSERT_GT(std::filesystem::file_size(wal_path, ec), 0U);

    auto loaded = kasumi::state_storage::load_state(fixture.database_path());
    ASSERT_TRUE(loaded.has_value());
    ASSERT_TRUE(loaded->has_value());
    EXPECT_EQ((*loaded)->height, 2U);

    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Ready);
}

TEST(ApplicationProfileTest,
     InspectLocalStatePendingMaterializationsInWalIsPending) {
    ProfileFixture fixture{"app-profile-state-wal-pending"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    auto reader = WalReaderGuard::open_and_hold_reader(fixture.database_path());
    ASSERT_TRUE(reader.has_value());
    ASSERT_TRUE(save_height(fixture.database_path(), 2, true));
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Pending);
}

TEST(ApplicationProfileTest,
     InspectLocalStatePendingMaterializationsInTableIsPending) {
    ProfileFixture fixture{"app-profile-state-pending"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1, true));
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Pending);
}

TEST(ApplicationProfileTest, InspectLocalStateRollbackJournalIsPending) {
    ProfileFixture fixture{"app-profile-state-journal"};
    const auto journal_file = fixture.profile_dir() / "db.sqlite-journal";
    auto writer = kasumi::sqlite::open(
        fixture.database_path(), SQLITE_OPEN_READWRITE);
    ASSERT_TRUE(writer.has_value());
    ASSERT_TRUE(kasumi::sqlite::execute(writer->get(),
                                        "PRAGMA journal_mode=DELETE"));
    ASSERT_TRUE(kasumi::sqlite::execute(writer->get(), "BEGIN EXCLUSIVE"));
    ASSERT_TRUE(kasumi::sqlite::execute(
        writer->get(), "CREATE TABLE interrupted_write (value INTEGER)"));
    ASSERT_TRUE(std::filesystem::exists(journal_file));
    ASSERT_GT(std::filesystem::file_size(journal_file), 0U);
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Pending);
    EXPECT_TRUE(kasumi::sqlite::execute(writer->get(), "ROLLBACK"));
}

TEST(ApplicationProfileTest,
     InspectRejectsRollbackJournalRemovedAfterSnapshotPreflight) {
    ProfileFixture fixture{"app-profile-rollback-journal-disappears"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    auto writer = kasumi::sqlite::open(
        fixture.database_path(), SQLITE_OPEN_READWRITE);
    ASSERT_TRUE(writer.has_value());
    ASSERT_TRUE(kasumi::sqlite::execute(writer->get(),
                                        "PRAGMA journal_mode=DELETE"));
    ASSERT_TRUE(kasumi::sqlite::execute(writer->get(), "BEGIN EXCLUSIVE"));
    ASSERT_TRUE(kasumi::sqlite::execute(
        writer->get(), "CREATE TABLE interrupted_write (value INTEGER)"));
    const auto rollback = fixture.profile_dir() / "db.sqlite-journal";
    ASSERT_TRUE(std::filesystem::exists(rollback));
    ASSERT_GT(std::filesystem::file_size(rollback), 0U);

    bool barrier_reached = false;
    bool rollback_succeeded = false;
    bool journal_removed = false;
    ScopedTempRoot temp(fixture.workspace);
    auto state = kasumi::application::ProfileLocalState::Ready;
    {
        kasumi::application::fault_test::ScopedInspectFaultInjection fault(
            kasumi::application::fault_test::InspectFaultStage::
                ConcurrentSnapshotBarrier,
            [&](kasumi::application::fault_test::InspectFaultStage stage) {
                if (stage == kasumi::application::fault_test::
                                 InspectFaultStage::ConcurrentSnapshotBarrier) {
                    barrier_reached = true;
                    rollback_succeeded = static_cast<bool>(
                        kasumi::sqlite::execute(writer->get(), "ROLLBACK"));
                    journal_removed = rollback_succeeded &&
                                      !std::filesystem::exists(rollback);
                }
            });
        state = kasumi::application::inspect_profile_local_state(
            fixture.environment, "main");
    }

    EXPECT_TRUE(barrier_reached);
    EXPECT_TRUE(rollback_succeeded);
    EXPECT_TRUE(journal_removed);
    EXPECT_EQ(state, kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(temp.inspection_directories().empty());
}

TEST(ApplicationProfileTest, InspectLocalStateKasumiSyncJournalIsPending) {
    ProfileFixture fixture{"app-profile-state-sync-journal"};
    const auto key_bytes =
        kasumi::runtime::vault::read_only(fixture.key_path());
    ASSERT_TRUE(key_bytes.has_value());
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, kasumi::make_sync_plan({}, 0));
    ASSERT_TRUE(record.has_value());
    auto journal_paths =
        kasumi::application::sync::journal::make_paths(fixture.profile_dir());
    ASSERT_TRUE(journal_paths.has_value());
    ASSERT_TRUE(kasumi::application::sync::journal::save(
        *journal_paths, *record, *key_bytes));
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Pending);
}

TEST(ApplicationProfileTest,
     InspectActiveJournalDoesNotHideCorruptedDatabase) {
    ProfileFixture fixture{"app-profile-state-corrupt-db-active-journal"};
    const auto key_bytes =
        kasumi::runtime::vault::read_only(fixture.key_path());
    ASSERT_TRUE(key_bytes.has_value());
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, kasumi::make_sync_plan({}, 0));
    ASSERT_TRUE(record.has_value());
    auto journal_paths =
        kasumi::application::sync::journal::make_paths(fixture.profile_dir());
    ASSERT_TRUE(journal_paths.has_value());
    ASSERT_TRUE(kasumi::application::sync::journal::save(
        *journal_paths, *record, *key_bytes));
    kasumi::test::write_text(fixture.database_path(), "not a SQLite database");

    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
}

TEST(ApplicationProfileTest, InspectDetectsJournalCreatedDuringSnapshot) {
    ProfileFixture fixture{"app-profile-state-late-sync-journal"};
    const auto key_bytes =
        kasumi::runtime::vault::read_only(fixture.key_path());
    ASSERT_TRUE(key_bytes.has_value());
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, kasumi::make_sync_plan({}, 0));
    ASSERT_TRUE(record.has_value());
    auto journal_paths =
        kasumi::application::sync::journal::make_paths(fixture.profile_dir());
    ASSERT_TRUE(journal_paths.has_value());
    bool journal_created = false;
    kasumi::application::fault_test::ScopedInspectFaultInjection fault(
        kasumi::application::fault_test::InspectFaultStage::AfterTempDirCreated,
        [&](kasumi::application::fault_test::InspectFaultStage) {
            journal_created = kasumi::application::sync::journal::save(
                *journal_paths, *record, *key_bytes).has_value();
        });

    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Pending);
    EXPECT_TRUE(journal_created);
}

TEST(ApplicationProfileTest,
     InspectLocalStateCorruptedKasumiJournalIsProblem) {
    ProfileFixture fixture{"app-profile-state-corrupt-journal"};
    const auto journal_dir = fixture.profile_dir() / "transaction.bin.enc";
    std::filesystem::create_directories(journal_dir);
    std::ofstream fake_snapshot(journal_dir / "snapshot.enc", std::ios::binary);
    fake_snapshot << "corrupted random data not matching magic header";
    fake_snapshot.close();
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
}

TEST(ApplicationProfileTest,
     InspectLocalStateAcceptedStateWithKasumiJournalIsPending) {
    ProfileFixture fixture{"app-profile-state-accepted-sync-journal"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    const auto key_bytes =
        kasumi::runtime::vault::read_only(fixture.key_path());
    ASSERT_TRUE(key_bytes.has_value());
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, kasumi::make_sync_plan({}, 0));
    ASSERT_TRUE(record.has_value());
    auto journal_paths =
        kasumi::application::sync::journal::make_paths(fixture.profile_dir());
    ASSERT_TRUE(journal_paths.has_value());
    auto saved = kasumi::application::sync::journal::save(
        *journal_paths, *record, *key_bytes);
    ASSERT_TRUE(saved.has_value()) << saved.error();
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Pending);
}

TEST(ApplicationProfileTest,
     InspectLocalStateRetiredKasumiJournalIsReady) {
    ProfileFixture fixture{"app-profile-state-retired-journal"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    const auto key_bytes =
        kasumi::runtime::vault::read_only(fixture.key_path());
    ASSERT_TRUE(key_bytes.has_value());
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, kasumi::make_sync_plan({}, 0));
    ASSERT_TRUE(record.has_value());
    auto journal_paths =
        kasumi::application::sync::journal::make_paths(fixture.profile_dir());
    ASSERT_TRUE(journal_paths.has_value());
    ASSERT_TRUE(kasumi::application::sync::journal::save(
        *journal_paths, *record, *key_bytes));
    ASSERT_TRUE(kasumi::application::sync::journal::clear(
        *journal_paths, *key_bytes));
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Ready);
}

TEST(ApplicationProfileTest,
     InspectLocalStateInconsistentRetiredMarkerIsProblem) {
    ProfileFixture fixture{"app-profile-state-inconsistent-retired"};
    const auto journal_dir = fixture.profile_dir() / "transaction.bin.enc";
    std::filesystem::create_directories(journal_dir);
    std::ofstream fake_retired(journal_dir / "retired.enc", std::ios::binary);
    fake_retired << "forged unauthenticated retired marker";
    fake_retired.close();
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
}

TEST(ApplicationProfileTest,
     InspectLocalStateEmptyRetiredDirectoryIsProblem) {
    ProfileFixture fixture{"app-profile-state-empty-retired"};
    std::filesystem::create_directories(fixture.profile_dir() /
                                        "transaction.bin.enc.cleared");
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
}

TEST(ApplicationProfileTest,
     InspectLocalStateCoexistingActiveAndRetiredJournalsIsProblem) {
    ProfileFixture fixture{"app-profile-state-coexist-journals"};
    std::filesystem::create_directories(fixture.profile_dir() /
                                        "transaction.bin.enc");
    std::filesystem::create_directories(fixture.profile_dir() /
                                        "transaction.bin.enc.cleared");
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
}

TEST(ApplicationProfileTest,
     InspectLocalStateMissingOrCorruptedArtifactsIsProblem) {
    ProfileFixture fixture{"app-profile-state-corrupt"};
    std::filesystem::remove(fixture.key_path());
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);

    std::ofstream bad_key(fixture.key_path(), std::ios::binary);
    bad_key << std::string(31, 'a');
    bad_key.close();
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);

    std::ofstream good_key(fixture.key_path(), std::ios::binary);
    good_key << std::string(32, 'a');
    good_key.close();

    std::filesystem::remove(fixture.database_path());
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
}

TEST(ApplicationProfileTest, InspectLocalStateJunctionIsProblem) {
#if defined(_WIN32)
    auto workspace =
        kasumi::test::make_temp_workspace("app-profile-state-junction");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    std::filesystem::create_directories(environment.app_data_dir / "profiles");

    auto target_dir =
        kasumi::test::workspace_path(workspace, "junction_target");
    std::filesystem::create_directories(target_dir);
    auto junction_dir =
        environment.app_data_dir / "profiles" / "junction_prof";
    std::string command = "cmd.exe /c mklink /J \"" + junction_dir.string() +
                          "\" \"" + target_dir.string() + "\"";
    if (std::system(command.c_str()) != 0) {
        GTEST_SKIP() << "junction creation is unavailable";
    }
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(environment,
                                                         "junction_prof"),
        kasumi::application::ProfileLocalState::Problem);
#endif
}

TEST(ApplicationProfileTest, InspectLockPathDirectoryIsProblem) {
    ProfileFixture fixture{"app-profile-state-lock-directory"};
    const auto lock_path =
        fixture.environment.app_data_dir / "profile-main.lock";
    ASSERT_TRUE(std::filesystem::create_directory(lock_path));
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
}

TEST(ApplicationProfileTest, InspectAvailableLockIsReadOnlyAndInactive) {
    ProfileFixture fixture{"app-profile-state-lock-available"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    const auto lock_path =
        fixture.environment.app_data_dir / "profile-main.lock";
    {
        std::ofstream stream(lock_path, std::ios::binary);
        stream << "available lock contents";
    }
    const auto before = capture_path(lock_path);
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Ready);
    EXPECT_EQ(before, capture_path(lock_path));
}

TEST(ApplicationProfileTest, InspectLockSymlinkIsProblem) {
    ProfileFixture fixture{"app-profile-state-lock-symlink"};
    const auto lock_path =
        fixture.environment.app_data_dir / "profile-main.lock";
    const auto target =
        kasumi::test::workspace_path(fixture.workspace, "outside-lock");
    ASSERT_TRUE(std::filesystem::create_directory(target));
#if defined(_WIN32)
    const std::string command = "cmd.exe /c mklink /J \"" +
                                lock_path.string() + "\" \"" +
                                target.string() + "\"";
    ASSERT_EQ(std::system(command.c_str()), 0);
#else
    std::error_code error;
    std::filesystem::remove(target);
    {
        std::ofstream stream(target, std::ios::binary);
        stream << "external lock target";
    }
    std::filesystem::create_symlink(target, lock_path, error);
    ASSERT_FALSE(error) << error.message();
#endif
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
}

TEST(ApplicationProfileTest, InspectLockOpenAndAcquireErrorsAreProblem) {
    ProfileFixture fixture{"app-profile-state-lock-errors"};
    const auto lock_path =
        fixture.environment.app_data_dir / "profile-main.lock";
    {
        std::ofstream stream(lock_path, std::ios::binary);
        stream << "available lock";
    }
    for (const auto stage : {
             kasumi::application::fault_test::InspectFaultStage::FailLockOpen,
             kasumi::application::fault_test::InspectFaultStage::
                 FailLockAcquire}) {
        kasumi::application::fault_test::ScopedInspectFaultInjection fault(
            stage, nullptr, lock_path);
        EXPECT_EQ(
            kasumi::application::inspect_profile_local_state(
                fixture.environment, "main"),
            kasumi::application::ProfileLocalState::Problem);
    }
}

TEST(ApplicationProfileTest, InspectSidecarMetadataErrorIsProblem) {
    ProfileFixture fixture{"app-profile-state-metadata-error"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    const auto wal_path = fixture.profile_dir() / "db.sqlite-wal";
    kasumi::application::fault_test::ScopedInspectFaultInjection fault(
        kasumi::application::fault_test::InspectFaultStage::FailMetadataQuery,
        nullptr,
        wal_path);
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
}

TEST(ApplicationProfileTest, InspectLockPathUnreadableIsProblem) {
    ProfileFixture fixture{"app-profile-state-lock-unreadable"};
    const auto lock_path =
        fixture.environment.app_data_dir / "profile-main.lock";
    {
        std::ofstream stream(lock_path, std::ios::binary);
        stream << "lock";
    }
    ScopedDeniedRead denied(lock_path);
    if (!denied.active()) {
        GTEST_SKIP() << "access denial is unavailable";
    }
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(denied.restore());
}

TEST(ApplicationProfileTest, InspectActiveProfileLockIsProblem) {
    ProfileFixture fixture{"app-profile-state-lock-active"};
    auto held = kasumi::platform::acquire_profile_lock(
        fixture.environment.app_data_dir / "profile-main.lock");
    ASSERT_TRUE(held.has_value());
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    kasumi::platform::release_profile_lock(*held);
}

TEST(ApplicationProfileTest,
     InspectLocalStateHasNoSideEffectsWithWalAndShm) {
    ProfileFixture fixture{"app-profile-state-sideeffects"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    const auto ready =
        kasumi::test::workspace_path(fixture.workspace, "writer-ready");
    const auto trigger =
        kasumi::test::workspace_path(fixture.workspace, "writer-trigger");
    const auto done =
        kasumi::test::workspace_path(fixture.workspace, "writer-done");
    const auto release =
        kasumi::test::workspace_path(fixture.workspace, "writer-release");
    auto child = launch_inspection_writer("hold",
                                          fixture.database_path(),
                                          ready,
                                          trigger,
                                          done,
                                          release);
    ASSERT_TRUE(child.has_value());
    ASSERT_TRUE(child->wait_for(ready, std::chrono::seconds{10}));

    const auto wal_path = fixture.profile_dir() / "db.sqlite-wal";
    const auto shm_path = fixture.profile_dir() / "db.sqlite-shm";
    ASSERT_TRUE(std::filesystem::exists(wal_path));
    ASSERT_TRUE(std::filesystem::exists(shm_path));

    const auto before = capture_directory_snapshot(fixture.profile_dir());
    const auto app_data_before =
        capture_directory_snapshot(fixture.environment.app_data_dir);
    ASSERT_FALSE(before.empty());
    EXPECT_TRUE(before.contains("db.sqlite-wal"));
    EXPECT_TRUE(before.contains("db.sqlite-shm"));

    for (int i = 0; i < 5; ++i) {
        EXPECT_EQ(
            kasumi::application::inspect_profile_local_state(
                fixture.environment, "main"),
            kasumi::application::ProfileLocalState::Ready);
    }

    EXPECT_EQ(before, capture_directory_snapshot(fixture.profile_dir()));
    EXPECT_EQ(app_data_before,
              capture_directory_snapshot(fixture.environment.app_data_dir));
    ASSERT_TRUE(create_signal(release));
    EXPECT_EQ(child->wait_for_exit(std::chrono::seconds{10}), 0);
}

TEST(ApplicationProfileTest,
     InspectLocalStateDoesNotCreateSqliteSidecars) {
    ProfileFixture fixture{"app-profile-state-no-sidecars"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    ASSERT_TRUE(remove_sidecars_after_checkpoint(fixture.database_path()));
    const auto wal_path = fixture.profile_dir() / "db.sqlite-wal";
    const auto shm_path = fixture.profile_dir() / "db.sqlite-shm";
    ASSERT_FALSE(std::filesystem::exists(wal_path));
    ASSERT_FALSE(std::filesystem::exists(shm_path));

    const auto before = capture_directory_snapshot(fixture.profile_dir());
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Ready);
    EXPECT_EQ(before, capture_directory_snapshot(fixture.profile_dir()));
    EXPECT_FALSE(std::filesystem::exists(wal_path));
    EXPECT_FALSE(std::filesystem::exists(shm_path));
}

TEST(ApplicationProfileTest,
     InspectReadsWalWithoutSharedMemoryWithoutSideEffects) {
    ProfileFixture writer_fixture{"app-profile-wal-only-writer"};
    ProfileFixture wal_only_fixture{"app-profile-wal-only-reader"};
    ASSERT_TRUE(save_height(writer_fixture.database_path(), 1));

    const auto ready = kasumi::test::workspace_path(
        writer_fixture.workspace, "writer-ready");
    const auto trigger = kasumi::test::workspace_path(
        writer_fixture.workspace, "writer-trigger");
    const auto done = kasumi::test::workspace_path(
        writer_fixture.workspace, "writer-done");
    const auto release = kasumi::test::workspace_path(
        writer_fixture.workspace, "writer-release");
    auto child = launch_inspection_writer("hold",
                                          writer_fixture.database_path(),
                                          ready,
                                          trigger,
                                          done,
                                          release);
    ASSERT_TRUE(child.has_value());
    ASSERT_TRUE(child->wait_for(ready, std::chrono::seconds{10}));

    const auto source_db = writer_fixture.database_path();
    const auto source_wal =
        std::filesystem::path(source_db.string() + "-wal");
    const auto target_db = wal_only_fixture.database_path();
    const auto target_wal =
        std::filesystem::path(target_db.string() + "-wal");
    std::error_code error;
    ASSERT_TRUE(std::filesystem::remove(target_db, error));
    ASSERT_FALSE(error);
    ASSERT_TRUE(std::filesystem::copy_file(
        source_db, target_db, std::filesystem::copy_options::overwrite_existing,
        error));
    ASSERT_FALSE(error);
    ASSERT_TRUE(std::filesystem::copy_file(source_wal, target_wal, error));
    ASSERT_FALSE(error);

    const auto target_shm =
        std::filesystem::path(target_db.string() + "-shm");
    ASSERT_FALSE(std::filesystem::exists(target_shm));
    const auto before = capture_directory_snapshot(wal_only_fixture.profile_dir());
    ScopedTempRoot temp(wal_only_fixture.workspace);
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(
            wal_only_fixture.environment, "main"),
        kasumi::application::ProfileLocalState::Ready);
    EXPECT_TRUE(temp.inspection_directories().empty());
    EXPECT_EQ(before,
              capture_directory_snapshot(wal_only_fixture.profile_dir()));
    EXPECT_FALSE(std::filesystem::exists(target_shm));
    ASSERT_TRUE(create_signal(release));
    EXPECT_EQ(child->wait_for_exit(std::chrono::seconds{10}), 0);
}

TEST(ApplicationProfileTest, InspectDoesNotRecreateWalRemovedAfterPreflight) {
    ProfileFixture writer_fixture{"app-profile-wal-disappears-writer"};
    ProfileFixture target_fixture{"app-profile-wal-disappears-target"};
    ASSERT_TRUE(save_height(writer_fixture.database_path(), 1));

    const auto ready =
        kasumi::test::workspace_path(writer_fixture.workspace, "writer-ready");
    const auto trigger = kasumi::test::workspace_path(
        writer_fixture.workspace, "writer-trigger");
    const auto done =
        kasumi::test::workspace_path(writer_fixture.workspace, "writer-done");
    const auto release = kasumi::test::workspace_path(
        writer_fixture.workspace, "writer-release");
    auto child = launch_inspection_writer("hold",
                                          writer_fixture.database_path(),
                                          ready,
                                          trigger,
                                          done,
                                          release);
    ASSERT_TRUE(child.has_value());
    ASSERT_TRUE(child->wait_for(ready, std::chrono::seconds{10}));

    const auto source_db = writer_fixture.database_path();
    const auto target_db = target_fixture.database_path();
    const auto source_wal =
        std::filesystem::path(source_db.string() + "-wal");
    const auto source_shm =
        std::filesystem::path(source_db.string() + "-shm");
    const auto target_wal =
        std::filesystem::path(target_db.string() + "-wal");
    const auto target_shm =
        std::filesystem::path(target_db.string() + "-shm");
    std::error_code error;
    ASSERT_TRUE(std::filesystem::remove(target_db, error));
    ASSERT_FALSE(error);
    for (const auto& [source, target] :
         {std::pair{source_db, target_db},
          std::pair{source_wal, target_wal},
          std::pair{source_shm, target_shm}}) {
        ASSERT_TRUE(std::filesystem::copy_file(
            source, target, std::filesystem::copy_options::overwrite_existing,
            error))
            << error.message();
        ASSERT_FALSE(error);
    }
    const auto before = capture_directory_snapshot(target_fixture.profile_dir());
    auto expected = before;
    expected.erase("db.sqlite-wal");
    bool wal_removed = false;
    ScopedTempRoot temp(target_fixture.workspace);
    kasumi::application::ProfileLocalState state =
        kasumi::application::ProfileLocalState::Problem;
    {
        kasumi::application::fault_test::ScopedInspectFaultInjection fault(
            kasumi::application::fault_test::InspectFaultStage::
                AfterTempDirCreated,
            [&](kasumi::application::fault_test::InspectFaultStage stage) {
                if (stage == kasumi::application::fault_test::InspectFaultStage::
                                 AfterTempDirCreated) {
                    wal_removed = std::filesystem::remove(target_wal, error) &&
                                  !error;
                }
            });
        state = kasumi::application::inspect_profile_local_state(
            target_fixture.environment, "main");
    }

    EXPECT_TRUE(wal_removed);
    EXPECT_EQ(state, kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(temp.inspection_directories().empty());
    EXPECT_EQ(expected,
              capture_directory_snapshot(target_fixture.profile_dir()));
    EXPECT_FALSE(std::filesystem::exists(target_wal));
    ASSERT_TRUE(create_signal(release));
    EXPECT_EQ(child->wait_for_exit(std::chrono::seconds{10}), 0);
}

TEST(ApplicationProfileTest, InspectSeesWalCreatedAfterPreflight) {
    ProfileFixture fixture{"app-profile-wal-created-after-preflight"};
    const auto ready =
        kasumi::test::workspace_path(fixture.workspace, "writer-ready");
    const auto trigger =
        kasumi::test::workspace_path(fixture.workspace, "writer-trigger");
    const auto done =
        kasumi::test::workspace_path(fixture.workspace, "writer-done");
    const auto release =
        kasumi::test::workspace_path(fixture.workspace, "writer-release");
    const auto wal =
        std::filesystem::path{fixture.database_path().string() + "-wal"};
    const auto shm =
        std::filesystem::path{fixture.database_path().string() + "-shm"};
    ASSERT_FALSE(std::filesystem::exists(wal));
    ASSERT_FALSE(std::filesystem::exists(shm));

    auto child = launch_inspection_writer("late-write",
                                          fixture.database_path(),
                                          ready,
                                          trigger,
                                          done,
                                          release);
    ASSERT_TRUE(child.has_value());
    ASSERT_TRUE(child->wait_for(ready, std::chrono::seconds{10}));

    bool preflight_saw_no_sidecars = false;
    bool writer_committed = false;
    std::map<std::string, FileSnapshot> before_inspection;
    std::map<std::string, FileSnapshot> app_data_before;
    ScopedTempRoot temp(fixture.workspace);
    auto state = kasumi::application::ProfileLocalState::Problem;
    {
        kasumi::application::fault_test::ScopedInspectFaultInjection fault(
            kasumi::application::fault_test::InspectFaultStage::
                AfterTempDirCreated,
            [&](kasumi::application::fault_test::InspectFaultStage stage) {
                if (stage != kasumi::application::fault_test::
                                 InspectFaultStage::AfterTempDirCreated) {
                    return;
                }
                preflight_saw_no_sidecars =
                    !std::filesystem::exists(wal) &&
                    !std::filesystem::exists(shm);
                writer_committed = create_signal(trigger) &&
                                   child->wait_for(done,
                                                   std::chrono::seconds{10});
                before_inspection =
                    capture_directory_snapshot(fixture.profile_dir());
                app_data_before = capture_directory_snapshot(
                    fixture.environment.app_data_dir);
            });
        state = kasumi::application::inspect_profile_local_state(
            fixture.environment, "main");
    }
    const auto profile_after =
        capture_directory_snapshot(fixture.profile_dir());
    const auto app_data_after =
        capture_directory_snapshot(fixture.environment.app_data_dir);
    const bool wal_has_commit =
        std::filesystem::exists(wal) && std::filesystem::file_size(wal) > 0;
    ASSERT_TRUE(create_signal(release));
    EXPECT_EQ(child->wait_for_exit(std::chrono::seconds{10}), 0);

    EXPECT_TRUE(preflight_saw_no_sidecars);
    EXPECT_TRUE(writer_committed);
    EXPECT_TRUE(wal_has_commit);
    EXPECT_EQ(state, kasumi::application::ProfileLocalState::Ready);
    EXPECT_EQ(before_inspection, profile_after);
    EXPECT_EQ(app_data_before, app_data_after);
    EXPECT_TRUE(temp.inspection_directories().empty());
}

TEST(ApplicationProfileTest,
     InspectKeepsEarlierReadySnapshotWhenPendingWalAppearsAtBarrier) {
    ProfileFixture fixture{"app-profile-wal-created-at-snapshot-barrier"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    const auto wal = fixture.profile_dir() / "db.sqlite-wal";
    const auto shm = fixture.profile_dir() / "db.sqlite-shm";
    auto initial = kasumi::state_storage::load_state(fixture.database_path());
    ASSERT_TRUE(initial.has_value());
    ASSERT_TRUE(initial->has_value());
    ASSERT_EQ(initial->value().height, 1U);
    ASSERT_TRUE(initial->value().pending_materializations.empty());
    ASSERT_TRUE(remove_sidecars_after_checkpoint(fixture.database_path()));
    ASSERT_FALSE(std::filesystem::exists(wal));
    ASSERT_FALSE(std::filesystem::exists(shm));
    const auto database_before = capture_path(fixture.database_path());

    const auto ready =
        kasumi::test::workspace_path(fixture.workspace, "writer-ready");
    const auto trigger =
        kasumi::test::workspace_path(fixture.workspace, "writer-trigger");
    const auto done =
        kasumi::test::workspace_path(fixture.workspace, "writer-done");
    const auto release =
        kasumi::test::workspace_path(fixture.workspace, "writer-release");
    auto child = launch_inspection_writer("late-pending",
                                          fixture.database_path(),
                                          ready,
                                          trigger,
                                          done,
                                          release);
    ASSERT_TRUE(child.has_value());
    ASSERT_TRUE(child->wait_for(ready, std::chrono::seconds{10}));

    bool barrier_saw_no_wal = false;
    bool writer_committed = false;
    bool wal_was_readable = false;
    bool main_database_unchanged_after_writer = false;
    bool copy_kept_initial_state = false;
    ScopedTempRoot temp(fixture.workspace);
    auto state = kasumi::application::ProfileLocalState::Problem;
    {
        kasumi::application::fault_test::ScopedInspectFaultInjection fault(
            kasumi::application::fault_test::InspectFaultStage::
                ConcurrentSnapshotBarrier,
            [&](kasumi::application::fault_test::InspectFaultStage stage) {
                if (stage == kasumi::application::fault_test::
                                 InspectFaultStage::ConcurrentSnapshotBarrier) {
                    barrier_saw_no_wal = !std::filesystem::exists(wal) &&
                                         !std::filesystem::exists(shm);
                    writer_committed = create_signal(trigger) &&
                                       child->wait_for(
                                           done, std::chrono::seconds{10});
                    std::error_code wal_error;
                    const auto wal_size =
                        std::filesystem::file_size(wal, wal_error);
                    auto confirmed =
                        kasumi::state_storage::load_state(fixture.database_path());
                    wal_was_readable =
                        !wal_error && wal_size > 32 && confirmed &&
                        confirmed->has_value() &&
                        confirmed->value().height == 3U &&
                        !confirmed->value().pending_materializations.empty();
                    main_database_unchanged_after_writer =
                        capture_path(fixture.database_path()).sha256 ==
                        database_before.sha256;
                } else if (stage == kasumi::application::fault_test::
                                        InspectFaultStage::SnapshotDatabaseCopied) {
                    const auto directories = temp.inspection_directories();
                    if (directories.size() == 1) {
                        auto copied = kasumi::state_storage::load_state(
                            *directories.begin() / "db.sqlite");
                        copy_kept_initial_state =
                            copied && copied->has_value() &&
                            copied->value().height == 1U &&
                            copied->value().pending_materializations.empty();
                    }
                }
            });
        state = kasumi::application::inspect_profile_local_state(
            fixture.environment, "main");
    }
    ASSERT_TRUE(create_signal(release));
    EXPECT_EQ(child->wait_for_exit(std::chrono::seconds{10}), 0);

    EXPECT_EQ(state, kasumi::application::ProfileLocalState::Ready);
    EXPECT_TRUE(barrier_saw_no_wal);
    EXPECT_TRUE(writer_committed);
    EXPECT_TRUE(wal_was_readable);
    EXPECT_TRUE(main_database_unchanged_after_writer);
    EXPECT_TRUE(copy_kept_initial_state);
    EXPECT_EQ(database_before.sha256, capture_path(fixture.database_path()).sha256);
    EXPECT_TRUE(temp.inspection_directories().empty());
}

TEST(ApplicationProfileTest,
     InspectRejectsRollbackPagesCopiedAcrossAnUncommittedRollback) {
    ProfileFixture fixture{"app-profile-rollback-spill-copy"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    {
        auto database = kasumi::sqlite::open(
            fixture.database_path(), SQLITE_OPEN_READWRITE);
        ASSERT_TRUE(database.has_value());
        ASSERT_TRUE(kasumi::sqlite::execute(database->get(),
                                            "PRAGMA journal_mode=DELETE"));
    }
    const auto wal = fixture.profile_dir() / "db.sqlite-wal";
    const auto shm = fixture.profile_dir() / "db.sqlite-shm";
    const auto rollback = fixture.profile_dir() / "db.sqlite-journal";
    ASSERT_FALSE(std::filesystem::exists(wal));
    ASSERT_FALSE(std::filesystem::exists(shm));
    ASSERT_FALSE(std::filesystem::exists(rollback));
    const auto database_before = capture_path(fixture.database_path());

    const auto ready =
        kasumi::test::workspace_path(fixture.workspace, "writer-ready");
    const auto trigger =
        kasumi::test::workspace_path(fixture.workspace, "writer-trigger");
    const auto done =
        kasumi::test::workspace_path(fixture.workspace, "writer-done");
    const auto release =
        kasumi::test::workspace_path(fixture.workspace, "writer-release");
    auto child = launch_inspection_writer("rollback-spill",
                                          fixture.database_path(),
                                          ready,
                                          trigger,
                                          done,
                                          release);
    ASSERT_TRUE(child.has_value());
    ASSERT_TRUE(child->wait_for(ready, std::chrono::seconds{10}));

    bool transaction_spilled = false;
    bool writer_blocked = false;
    bool writer_attempt_finished = false;
    bool rollback_was_present = false;
    bool copied_while_uncommitted = false;
    bool source_was_restored = false;
    bool source_mtime_changed_after_rollback = false;
    bool source_metadata_changed_after_rollback = false;
    bool database_copy_completed = false;
    std::uint64_t copied_height = 0;
    std::size_t copied_nodes = 0;
    bool copied_state_valid = false;
    ScopedTempRoot temp(fixture.workspace);
    auto state = kasumi::application::ProfileLocalState::Problem;
    {
        kasumi::application::fault_test::ScopedInspectFaultInjection fault(
            kasumi::application::fault_test::InspectFaultStage::
                ConcurrentSnapshotBarrier,
            [&](kasumi::application::fault_test::InspectFaultStage stage) {
                if (stage == kasumi::application::fault_test::
                                 InspectFaultStage::ConcurrentSnapshotBarrier) {
                    if (create_signal(trigger) &&
                        child->wait_for(done, std::chrono::seconds{10})) {
                        writer_attempt_finished = true;
                        std::ifstream status_file(done, std::ios::binary);
                        std::string status;
                        std::getline(status_file, status);
                        transaction_spilled = status == "spilled";
                        writer_blocked = status == "blocked";
                    }
                    rollback_was_present =
                        std::filesystem::exists(rollback) &&
                        std::filesystem::file_size(rollback) > 0;
                    if (transaction_spilled) {
                        const auto changed = capture_path(fixture.database_path());
                        copied_while_uncommitted =
                            changed.type == std::filesystem::file_type::regular &&
                            changed.size == database_before.size &&
                            changed.sha256 != database_before.sha256;
                    }
                } else if (stage == kasumi::application::fault_test::
                                        InspectFaultStage::SnapshotDatabaseCopied) {
                    database_copy_completed = true;
                    if (transaction_spilled) {
                        const bool released = create_signal(release);
                        const auto exit_code = child->wait_for_exit(
                            std::chrono::seconds{10});
                        const auto restored =
                            capture_path(fixture.database_path());
                        source_was_restored = released && exit_code == 0 &&
                                              restored.sha256 ==
                                                  database_before.sha256;
                        source_metadata_changed_after_rollback =
                            restored.mtime != database_before.mtime ||
                            restored.change_time !=
                                database_before.change_time;
                        source_mtime_changed_after_rollback =
                            restored.mtime != database_before.mtime;
                    } else {
                        create_signal(release);
                        child->wait_for_exit(std::chrono::seconds{10});
                    }
                } else if (stage == kasumi::application::fault_test::
                                        InspectFaultStage::SnapshotReady) {
                    auto copied = kasumi::state_storage::load_state(
                        kasumi::application::fault_test::g_inspect_fault_path);
                    if (copied && copied->has_value()) {
                        copied_state_valid = true;
                        copied_height = copied->value().height;
                        copied_nodes = copied->value().tree.rows.size();
                    }
                }
            });
        state = kasumi::application::inspect_profile_local_state(
            fixture.environment, "main");
    }
    if (!std::filesystem::exists(release)) {
        create_signal(release);
        child->wait_for_exit(std::chrono::seconds{10});
    }
    auto original_after = kasumi::state_storage::load_state(fixture.database_path());

    EXPECT_TRUE(writer_attempt_finished);
    EXPECT_TRUE(database_copy_completed);
    RecordProperty("writer_outcome",
                   transaction_spilled ? "spilled" : "blocked");
    RecordProperty("writer_attempt_finished",
                   writer_attempt_finished ? "true" : "false");
    RecordProperty("writer_blocked", writer_blocked ? "true" : "false");
    RecordProperty("rollback_file_present",
                   rollback_was_present ? "true" : "false");
    RecordProperty("copied_while_uncommitted",
                   copied_while_uncommitted ? "true" : "false");
    RecordProperty("source_restored_after_rollback",
                   source_was_restored ? "true" : "false");
    RecordProperty("native_metadata_changed_after_rollback",
                   source_metadata_changed_after_rollback ? "true" : "false");
    RecordProperty("mtime_changed_after_rollback",
                   source_mtime_changed_after_rollback ? "true" : "false");
    RecordProperty("inspection_result",
                   state == kasumi::application::ProfileLocalState::Problem
                       ? "Problem"
                       : "Ready");
    if (transaction_spilled) {
        EXPECT_EQ(state, kasumi::application::ProfileLocalState::Problem);
        EXPECT_TRUE(rollback_was_present);
        EXPECT_TRUE(copied_while_uncommitted);
        EXPECT_TRUE(source_was_restored);
        EXPECT_TRUE(source_mtime_changed_after_rollback);
        EXPECT_TRUE(source_metadata_changed_after_rollback);
        EXPECT_FALSE(copied_state_valid);
    } else {
        EXPECT_TRUE(writer_blocked);
        EXPECT_EQ(state, kasumi::application::ProfileLocalState::Ready);
        EXPECT_TRUE(copied_state_valid);
        EXPECT_EQ(copied_height, 1U);
        EXPECT_EQ(copied_nodes, 2U);
    }
    ASSERT_TRUE(original_after.has_value());
    ASSERT_TRUE(original_after->has_value());
    EXPECT_EQ(original_after->value().height, 1U);
    EXPECT_TRUE(original_after->value().pending_materializations.empty());
    EXPECT_FALSE(std::filesystem::exists(rollback));
    EXPECT_TRUE(temp.inspection_directories().empty());
}

TEST(ApplicationProfileTest, InspectTempDirFailsExplicitlyOnRandomIdFailure) {
    ProfileFixture fixture{"app-profile-rand-fail"};
    ScopedTempRoot temp(fixture.workspace);
    kasumi::application::fault_test::ScopedInspectFaultInjection fault(
        kasumi::application::fault_test::InspectFaultStage::FailRandomId);
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(temp.inspection_directories().empty());
}

TEST(ApplicationProfileTest,
     InspectTempDirCollisionPreservesPreexistingDirectory) {
    ProfileFixture fixture{"app-profile-coll-dir"};
    const auto colliding_path =
        kasumi::test::workspace_path(fixture.workspace, "collision");
    ASSERT_TRUE(std::filesystem::create_directory(colliding_path));
    kasumi::application::fault_test::ScopedInspectFaultInjection fault(
        kasumi::application::fault_test::InspectFaultStage::
            SimulateTempDirCollision,
        nullptr,
        colliding_path);
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(std::filesystem::is_directory(colliding_path));
}

TEST(ApplicationProfileTest,
     InspectTempDirCollisionPreservesImportantFiles) {
    ProfileFixture fixture{"app-profile-coll-files"};
    const auto colliding_path =
        kasumi::test::workspace_path(fixture.workspace, "collision");
    ASSERT_TRUE(std::filesystem::create_directory(colliding_path));
    const auto important_file = colliding_path / "important.txt";
    const std::string important_content = "CRITICAL USER DATA DO NOT DELETE";
    {
        std::ofstream stream(important_file, std::ios::binary);
        stream << important_content;
    }
    kasumi::application::fault_test::ScopedInspectFaultInjection fault(
        kasumi::application::fault_test::InspectFaultStage::
            SimulateTempDirCollision,
        nullptr,
        colliding_path);
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(std::filesystem::exists(important_file));
    std::string read_content;
    {
        std::ifstream stream(important_file, std::ios::binary);
        read_content.assign(std::istreambuf_iterator<char>(stream),
                            std::istreambuf_iterator<char>());
    }
    EXPECT_EQ(read_content, important_content);
}

TEST(ApplicationProfileTest,
     InspectSnapshotFailureLeavesNoTemporarySqliteCopies) {
    ProfileFixture fixture{"app-profile-snapshot-fail"};
    ScopedTempRoot temp(fixture.workspace);
    kasumi::application::fault_test::ScopedInspectFaultInjection fault(
        kasumi::application::fault_test::InspectFaultStage::FailSnapshot);
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(temp.inspection_directories().empty());
}

TEST(ApplicationProfileTest,
     InspectCleanupFailureReportsProblemAndRetainsOwnership) {
    ProfileFixture fixture{"app-profile-clean-fail"};
    ScopedTempRoot temp(fixture.workspace);
    kasumi::application::fault_test::ScopedInspectFaultInjection fault(
        kasumi::application::fault_test::InspectFaultStage::FailCleanup);
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(kasumi::application::fault_test::
                    g_inspect_cleanup_failure_consumed);
    EXPECT_TRUE(temp.inspection_directories().empty());
}

TEST(ApplicationProfileTest, InspectCleanupRetriesAfterFileRemovalFailure) {
    ProfileFixture fixture{"app-profile-clean-file-retry"};
    ScopedTempRoot temp(fixture.workspace);
    kasumi::application::fault_test::ScopedInspectFaultInjection fault(
        kasumi::application::fault_test::InspectFaultStage::
            FailCleanupFileRemove);
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(kasumi::application::fault_test::
                    g_inspect_cleanup_failure_consumed);
    EXPECT_TRUE(temp.inspection_directories().empty());
}

TEST(ApplicationProfileTest, InspectCleanupRetriesAfterDirectoryRemovalFailure) {
    ProfileFixture fixture{"app-profile-clean-directory-retry"};
    ScopedTempRoot temp(fixture.workspace);
    kasumi::application::fault_test::ScopedInspectFaultInjection fault(
        kasumi::application::fault_test::InspectFaultStage::
            FailCleanupDirectoryRemove);
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(kasumi::application::fault_test::
                    g_inspect_cleanup_failure_consumed);
    EXPECT_TRUE(temp.inspection_directories().empty());
}

TEST(ApplicationProfileTest,
     InspectSuccessfulOperationCleansUpTemporaryResources) {
    ProfileFixture fixture{"app-profile-succ-clean"};
    ScopedTempRoot temp(fixture.workspace);
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Initialized);
    EXPECT_TRUE(temp.inspection_directories().empty());
}

TEST(ApplicationProfileTest,
     InspectDirectoryIdentityFailureLeavesNoUnownedCleanup) {
    ProfileFixture fixture{"app-profile-inspect-identity-failure"};
    ScopedTempRoot temp(fixture.workspace);
    kasumi::application::fault_test::ScopedInspectFaultInjection fault(
        kasumi::application::fault_test::InspectFaultStage::
            FailDirectoryIdentity);

    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(kasumi::application::fault_test::
                    g_inspect_identity_failure_consumed);
    EXPECT_GT(kasumi::application::fault_test::g_inspect_cleanup_attempts, 0U);

    const auto directories = temp.inspection_directories();
    ASSERT_EQ(directories.size(), 1U);
    const auto candidate = *directories.begin();
    ASSERT_TRUE(std::filesystem::is_empty(candidate));
    std::error_code error;
    EXPECT_TRUE(std::filesystem::remove(candidate, error));
    EXPECT_FALSE(error);
    EXPECT_TRUE(temp.inspection_directories().empty());
}

TEST(ApplicationProfileTest,
     InspectCleanupRefusesUnknownEntriesAndPreservesThem) {
    ProfileFixture fixture{"app-profile-clean-unknown"};
    ScopedTempRoot temp(fixture.workspace);
    std::filesystem::path important_file;
    const std::string content = "external data must survive inspection cleanup";
    kasumi::application::fault_test::ScopedInspectFaultInjection fault(
        kasumi::application::fault_test::InspectFaultStage::
            AfterTempDirCreated,
        [&](kasumi::application::fault_test::InspectFaultStage) {
            const auto directories = temp.inspection_directories();
            if (directories.empty()) {
                return;
            }
            important_file = *directories.begin() / "important.txt";
            std::ofstream stream(important_file, std::ios::binary);
            stream << content;
        });
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    ASSERT_FALSE(important_file.empty());
    ASSERT_TRUE(std::filesystem::exists(important_file));
    std::ifstream stream(important_file, std::ios::binary);
    std::string read_content{std::istreambuf_iterator<char>(stream),
                             std::istreambuf_iterator<char>()};
    EXPECT_EQ(read_content, content);
}

TEST(ApplicationProfileTest,
     InspectCleanupRefusesSubstitutedTemporaryDirectory) {
    ProfileFixture fixture{"app-profile-clean-substitute"};
    ScopedTempRoot temp(fixture.workspace);
    std::filesystem::path replacement;
    const std::string content = "replacement data must survive";
    kasumi::application::fault_test::ScopedInspectFaultInjection fault(
        kasumi::application::fault_test::InspectFaultStage::
            AfterTempDirCreated,
        [&](kasumi::application::fault_test::InspectFaultStage) {
            const auto directories = temp.inspection_directories();
            if (directories.empty()) {
                return;
            }
            const auto original = *directories.begin();
            std::filesystem::rename(original, temp.root() / "moved-original");
            replacement = original;
            std::filesystem::create_directory(replacement);
            std::ofstream stream(replacement / "important.txt",
                                 std::ios::binary);
            stream << content;
        });
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    ASSERT_FALSE(replacement.empty());
    EXPECT_TRUE(std::filesystem::exists(replacement / "important.txt"));
    EXPECT_FALSE(std::filesystem::exists(replacement / "db.sqlite"));
    std::ifstream stream(replacement / "important.txt", std::ios::binary);
    std::string read_content{std::istreambuf_iterator<char>(stream),
                             std::istreambuf_iterator<char>()};
    EXPECT_EQ(read_content, content);
}

TEST(ApplicationProfileTest,
     InspectDoesNotTreatUnreadableWalAsAbsent) {
    ProfileFixture fixture{"app-profile-state-wal-denied"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    auto reader = WalReaderGuard::open_and_hold_reader(fixture.database_path());
    ASSERT_TRUE(reader.has_value());
    ASSERT_TRUE(save_height(fixture.database_path(), 2));
    const auto wal_path = fixture.profile_dir() / "db.sqlite-wal";
    ASSERT_TRUE(std::filesystem::exists(wal_path));
    ScopedDeniedRead denied(wal_path);
    if (!denied.active()) {
        GTEST_SKIP() << "access denial is unavailable";
    }
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(denied.restore());
}

TEST(ApplicationProfileTest, InspectDoesNotNeedReadableShm) {
    ProfileFixture fixture{"app-profile-state-shm-denied"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    auto reader = WalReaderGuard::open_and_hold_reader(fixture.database_path());
    ASSERT_TRUE(reader.has_value());
    ASSERT_TRUE(save_height(fixture.database_path(), 2));
    const auto shm_path = fixture.profile_dir() / "db.sqlite-shm";
    ASSERT_TRUE(std::filesystem::exists(shm_path));
    ScopedDeniedRead denied(shm_path);
    if (!denied.active()) {
        GTEST_SKIP() << "access denial is unavailable";
    }
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Ready);
    EXPECT_TRUE(denied.restore());
}

TEST(ApplicationProfileTest,
     InspectDoesNotTreatUnreadableRollbackJournalAsAbsent) {
    ProfileFixture fixture{"app-profile-state-journal-denied"};
    const auto journal_path = fixture.profile_dir() / "db.sqlite-journal";
    {
        std::ofstream stream(journal_path, std::ios::binary);
        stream << "rollback journal";
    }
    ScopedDeniedRead denied(journal_path);
    if (!denied.active()) {
        GTEST_SKIP() << "access denial is unavailable";
    }
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(denied.restore());
}

TEST(ApplicationProfileTest,
     InspectDoesNotHideCorruptedDatabaseBehindRollbackJournal) {
    ProfileFixture fixture{"app-profile-state-corrupt-db-rollback-journal"};
    const auto journal_path = fixture.profile_dir() / "db.sqlite-journal";
    {
        std::ofstream stream(journal_path, std::ios::binary);
        stream << "rollback journal evidence";
    }
    kasumi::test::write_text(fixture.database_path(), "not a SQLite database");
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
}

TEST(ApplicationProfileTest,
     InspectDoesNotTreatUnreadableDatabaseAsAbsent) {
    ProfileFixture fixture{"app-profile-state-db-denied"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    ScopedDeniedRead denied(fixture.database_path());
    if (!denied.active()) {
        GTEST_SKIP() << "access denial is unavailable";
    }
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(denied.restore());
}

TEST(ApplicationProfileTest,
     InspectJournalInspectionDoesNotModifyArtifacts) {
    ProfileFixture fixture{"app-profile-journal-passive"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    const auto key_bytes =
        kasumi::runtime::vault::read_only(fixture.key_path());
    ASSERT_TRUE(key_bytes.has_value());
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, kasumi::make_sync_plan({}, 0));
    ASSERT_TRUE(record.has_value());
    auto journal_paths =
        kasumi::application::sync::journal::make_paths(fixture.profile_dir());
    ASSERT_TRUE(journal_paths.has_value());
    ASSERT_TRUE(kasumi::application::sync::journal::save(
        *journal_paths, *record, *key_bytes));

    const auto journal_dir = journal_paths->final_path.parent_path();
    for (const auto& entry :
         std::filesystem::directory_iterator(journal_dir)) {
        if (entry.is_regular_file()) {
            ASSERT_TRUE(grant_everyone_read(entry.path()));
        }
    }

    const auto before = capture_directory_snapshot(fixture.profile_dir());
    for (int i = 0; i < 3; ++i) {
        EXPECT_EQ(kasumi::application::sync::journal::inspect(
                      *journal_paths, *key_bytes),
                  kasumi::application::sync::journal::InspectionResult::Active);
    }
    EXPECT_EQ(before, capture_directory_snapshot(fixture.profile_dir()));

    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Pending);
    EXPECT_EQ(before, capture_directory_snapshot(fixture.profile_dir()));
}

TEST(ApplicationProfileTest,
     InspectSnapshotIsConsistentUnderConcurrentWriter) {
    ProfileFixture fixture{"app-profile-concurrent-snapshot"};
    ASSERT_TRUE(save_height(fixture.database_path(), 1));
    const auto ready =
        kasumi::test::workspace_path(fixture.workspace, "writer-ready");
    const auto trigger =
        kasumi::test::workspace_path(fixture.workspace, "writer-trigger");
    const auto done =
        kasumi::test::workspace_path(fixture.workspace, "writer-done");
    const auto release =
        kasumi::test::workspace_path(fixture.workspace, "writer-release");
    auto child = launch_inspection_writer("write",
                                          fixture.database_path(),
                                          ready,
                                          trigger,
                                          done,
                                          release);
    ASSERT_TRUE(child.has_value());
    ASSERT_TRUE(child->wait_for(ready, std::chrono::seconds{10}));
    ASSERT_TRUE(std::filesystem::exists(fixture.profile_dir() / "db.sqlite-wal"));
    ASSERT_TRUE(std::filesystem::exists(fixture.profile_dir() / "db.sqlite-shm"));

    bool writer_committed_during_snapshot = false;
    bool snapshot_was_consistent = false;
    ScopedTempRoot temp(fixture.workspace);
    kasumi::application::ProfileLocalState state =
        kasumi::application::ProfileLocalState::Problem;
    {
        kasumi::application::fault_test::ScopedInspectFaultInjection fault(
            kasumi::application::fault_test::InspectFaultStage::
                ConcurrentSnapshotBarrier,
            [&](kasumi::application::fault_test::InspectFaultStage stage) {
                if (stage ==
                    kasumi::application::fault_test::InspectFaultStage::
                        ConcurrentSnapshotBarrier) {
                    writer_committed_during_snapshot =
                        create_signal(trigger) &&
                        child->wait_for(done, std::chrono::seconds{10});
                } else if (stage ==
                           kasumi::application::fault_test::InspectFaultStage::
                               SnapshotReady) {
                    const auto snapshot = kasumi::state_storage::load_state(
                        kasumi::application::fault_test::g_inspect_fault_path);
                    snapshot_was_consistent =
                        snapshot && snapshot->has_value() &&
                        (snapshot->value().height == 2 ||
                         snapshot->value().height == 3);
                }
            });
        state = kasumi::application::inspect_profile_local_state(
            fixture.environment, "main");
    }

    EXPECT_EQ(state, kasumi::application::ProfileLocalState::Problem);
    EXPECT_TRUE(writer_committed_during_snapshot);
    EXPECT_FALSE(snapshot_was_consistent);
    EXPECT_TRUE(temp.inspection_directories().empty());
    ASSERT_TRUE(create_signal(release));
    EXPECT_EQ(child->wait_for_exit(std::chrono::seconds{10}), 0);
}

TEST(ApplicationProfileTest,
     InspectLocalStateDoesNotCreateLockFilesOrModifyAppData) {
    ProfileFixture fixture{"app-profile-state-no-lock"};
    const auto before =
        capture_directory_snapshot(fixture.environment.app_data_dir);
    EXPECT_FALSE(std::filesystem::exists(fixture.environment.app_data_dir /
                                         "profile-main.lock"));
    EXPECT_EQ(
        kasumi::application::inspect_profile_local_state(fixture.environment,
                                                         "main"),
        kasumi::application::ProfileLocalState::Initialized);
    EXPECT_EQ(before,
              capture_directory_snapshot(fixture.environment.app_data_dir));
    EXPECT_FALSE(std::filesystem::exists(fixture.environment.app_data_dir /
                                         "profile-main.lock"));
}

} // namespace
