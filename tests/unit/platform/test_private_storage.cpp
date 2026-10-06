#include "kasumi/test/temp_workspace.hpp"
#include "platform/private_storage.hpp"
#include "platform/workspace.hpp"

#include <array>
#include <cstddef>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <aclapi.h>
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace {

#if defined(_WIN32)

void expect_private_dacl(const std::filesystem::path& path) {
    HANDLE token = nullptr;
    ASSERT_TRUE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    DWORD token_size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &token_size);
    std::vector<std::byte> token_data(token_size);
    ASSERT_TRUE(GetTokenInformation(
        token, TokenUser, token_data.data(), token_size, &token_size));
    CloseHandle(token);
    const auto* user = reinterpret_cast<const TOKEN_USER*>(token_data.data());
    std::array<std::byte, SECURITY_MAX_SID_SIZE> system_storage{};
    DWORD system_size = static_cast<DWORD>(system_storage.size());
    ASSERT_TRUE(CreateWellKnownSid(
        WinLocalSystemSid, nullptr, system_storage.data(), &system_size));

    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    ASSERT_EQ(GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()),
                                    SE_FILE_OBJECT,
                                    DACL_SECURITY_INFORMATION,
                                    nullptr,
                                    nullptr,
                                    &dacl,
                                    nullptr,
                                    &descriptor),
              ERROR_SUCCESS);
    ASSERT_NE(descriptor, nullptr);
    ASSERT_NE(dacl, nullptr);

    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    ASSERT_TRUE(GetSecurityDescriptorControl(descriptor, &control, &revision));
    EXPECT_NE(control & SE_DACL_PROTECTED, 0);

    ACL_SIZE_INFORMATION information{};
    ASSERT_TRUE(GetAclInformation(
        dacl, &information, sizeof(information), AclSizeInformation));
    EXPECT_EQ(information.AceCount, 2U);
    bool user_seen = false;
    bool system_seen = false;
    for (DWORD index = 0; index < information.AceCount; ++index) {
        void* raw = nullptr;
        ASSERT_TRUE(GetAce(dacl, index, &raw));
        const auto* header = static_cast<const ACE_HEADER*>(raw);
        EXPECT_EQ(header->AceType, ACCESS_ALLOWED_ACE_TYPE);
        EXPECT_EQ(header->AceFlags & INHERITED_ACE, 0);
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
        EXPECT_EQ(ace->Mask & FILE_ALL_ACCESS, FILE_ALL_ACCESS);
        auto* sid = const_cast<DWORD*>(&ace->SidStart);
        user_seen = user_seen || EqualSid(sid, user->User.Sid);
        system_seen = system_seen || EqualSid(sid, system_storage.data());
    }
    EXPECT_TRUE(user_seen);
    EXPECT_TRUE(system_seen);
    LocalFree(descriptor);
}

#else

void expect_mode(const std::filesystem::path& path, mode_t expected) {
    struct stat status{};
    ASSERT_EQ(::lstat(path.c_str(), &status), 0);
    EXPECT_EQ(status.st_mode & 0777, expected);
}

#endif

TEST(PrivateStorageTest, CreatesRestrictedDirectoryAndFile) {
    auto workspace =
        kasumi::test::make_temp_workspace("private-storage-permissions");
    const auto directory = kasumi::test::workspace_path(workspace, "private");
    const auto file = directory / "state.bin";

    ASSERT_TRUE(kasumi::platform::private_storage::create_directory(directory));
    ASSERT_TRUE(kasumi::platform::private_storage::create_file(file));

#if defined(_WIN32)
    expect_private_dacl(directory);
    expect_private_dacl(file);
#else
    expect_mode(directory, 0700);
    expect_mode(file, 0600);
#endif
}

#if defined(_WIN32)
TEST(PrivateStorageTest, RemovesWorkspaceWithNestedLongPath) {
    auto owner = kasumi::test::make_temp_workspace("long-workspace-cleanup");
    const auto root = kasumi::test::workspace_root(owner);
    auto nested = root;
    std::vector<std::filesystem::path> directories;
    const std::wstring segment(64, L'a');
    const std::wstring filename(64, L'b');
    while ((nested / filename).native().size() <= MAX_PATH) {
        nested /= segment;
        auto extended = L"\\\\?\\" + nested.wstring();
        ASSERT_TRUE(CreateDirectoryW(extended.c_str(), nullptr))
            << GetLastError();
        directories.push_back(nested);
    }
    const auto file = nested / filename;
    ASSERT_GT(file.native().size(), MAX_PATH);
    const auto extended_file = L"\\\\?\\" + file.wstring();
    const auto handle = CreateFileW(extended_file.c_str(),
                                    GENERIC_WRITE,
                                    0,
                                    nullptr,
                                    CREATE_NEW,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    ASSERT_NE(handle, INVALID_HANDLE_VALUE) << GetLastError();
    ASSERT_TRUE(CloseHandle(handle));

    const auto extended_root = L"\\\\?\\" + root.wstring();
    ASSERT_TRUE(kasumi::platform::private_storage::protect_tree(extended_root));
    expect_private_dacl(extended_file);

    const auto removed =
        kasumi::platform::remove_workspace(kasumi::platform::Workspace{root});
    EXPECT_TRUE(removed.has_value()) << (removed ? "" : removed.error());
    EXPECT_FALSE(std::filesystem::exists(root));
    if (!removed) {
        const auto extended_file_path = L"\\\\?\\" + file.wstring();
        static_cast<void>(DeleteFileW(extended_file_path.c_str()));
        for (auto iterator = directories.rbegin();
             iterator != directories.rend();
             ++iterator) {
            const auto extended_directory_path =
                L"\\\\?\\" + iterator->wstring();
            static_cast<void>(
                RemoveDirectoryW(extended_directory_path.c_str()));
        }
    }
}
#endif

TEST(PrivateStorageTest, AtomicWriteReplacesContentAndLeavesNoTemporaryFile) {
    auto workspace =
        kasumi::test::make_temp_workspace("private-storage-atomic");
    const auto directory = kasumi::test::workspace_path(workspace, "private");
    const auto file = directory / "config";
    ASSERT_TRUE(kasumi::platform::private_storage::create_directory(directory));
    ASSERT_TRUE(
        kasumi::platform::private_storage::write_atomically(file, "one"));
    ASSERT_TRUE(
        kasumi::platform::private_storage::write_atomically(file, "two"));

    std::ifstream input(file, std::ios::binary);
    std::string content{std::istreambuf_iterator<char>{input}, {}};
    EXPECT_EQ(content, "two");
    std::size_t entries = 0;
    for ([[maybe_unused]] const auto& entry :
         std::filesystem::directory_iterator(directory)) {
        ++entries;
    }
    EXPECT_EQ(entries, 1U);
}

TEST(PrivateStorageTest, RejectsRedirectingPaths) {
    auto workspace = kasumi::test::make_temp_workspace("private-storage-links");
    const auto target = kasumi::test::workspace_path(workspace, "target");
    const auto link = kasumi::test::workspace_path(workspace, "link");
    ASSERT_TRUE(std::filesystem::create_directory(target));
    std::error_code error;
    std::filesystem::create_directory_symlink(target, link, error);
    if (error) {
        GTEST_SKIP() << error.message();
    }
    EXPECT_FALSE(
        kasumi::platform::private_storage::protect_directory(link).has_value());
}

} // namespace
