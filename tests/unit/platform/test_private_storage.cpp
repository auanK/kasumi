#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/scoped_environment.hpp"
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
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
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

TEST(WorkspaceTest, RefusesToRemoveAReplacedDirectory) {
    auto fixture = kasumi::test::make_temp_workspace("workspace-replacement");
#if defined(_WIN32)
    const auto temporary_path = kasumi::test::workspace_root(fixture).wstring();
    const auto temp = kasumi::test::scoped_windows_environment_variable(
        L"TEMP", temporary_path);
    const auto tmp = kasumi::test::scoped_windows_environment_variable(
        L"TMP", temporary_path);
#else
    const auto temp = kasumi::test::scoped_environment_variable(
        "TMPDIR", kasumi::test::workspace_root(fixture).string());
#endif

    auto workspace = kasumi::platform::create_workspace("replacement");
    ASSERT_TRUE(workspace) << workspace.error();
    ASSERT_EQ(workspace->root.parent_path(),
              kasumi::test::workspace_root(fixture));

    kasumi::test::write_text(workspace->root / "original.txt", "original");
    const auto displaced = kasumi::test::workspace_root(fixture) / "displaced";
    std::error_code error;
    std::filesystem::rename(workspace->root, displaced, error);
    ASSERT_FALSE(error) << error.message();
    ASSERT_TRUE(std::filesystem::create_directory(workspace->root, error));
    ASSERT_FALSE(error) << error.message();
    const auto sentinel = workspace->root / "victim.txt";
    kasumi::test::write_text(sentinel, "keep this replacement");

    const auto removed = kasumi::platform::remove_workspace(*workspace);
    EXPECT_FALSE(removed);
    EXPECT_TRUE(std::filesystem::is_directory(workspace->root));
    ASSERT_TRUE(std::filesystem::exists(sentinel));
    EXPECT_EQ(kasumi::test::read_text(sentinel), "keep this replacement");
    EXPECT_TRUE(std::filesystem::is_directory(displaced));
    EXPECT_EQ(kasumi::test::read_text(displaced / "original.txt"), "original");
}

TEST(WorkspaceTest, RemovesDirectoryWithCapturedIdentity) {
    auto fixture = kasumi::test::make_temp_workspace("workspace-owned-removal");
    const auto root = kasumi::test::workspace_root(fixture) / "owned";
    auto workspace = kasumi::platform::create_workspace_at(root);
    ASSERT_TRUE(workspace) << workspace.error();
    kasumi::test::write_text(root / "owned.txt", "workspace data");

    const auto removed = kasumi::platform::remove_workspace(*workspace);
    ASSERT_TRUE(removed.has_value()) << removed.error();
    EXPECT_FALSE(std::filesystem::exists(root));
}

TEST(WorkspaceTest, PathOnlyWorkspaceCannotRemoveExistingDirectory) {
    auto fixture = kasumi::test::make_temp_workspace("workspace-unknown-owner");
    const auto root = kasumi::test::workspace_root(fixture) / "unowned";
    ASSERT_TRUE(std::filesystem::create_directory(root));
    kasumi::test::write_text(root / "keep.txt", "unowned data");

    const auto removed =
        kasumi::platform::remove_workspace({.root = root});
    EXPECT_FALSE(removed.has_value());
    EXPECT_EQ(kasumi::test::read_text(root / "keep.txt"), "unowned data");
}

#if defined(_WIN32)
TEST(PrivateStorageTest, RemovesWorkspaceWithNestedLongPath) {
    auto owner = kasumi::test::make_temp_workspace("long-workspace-cleanup");
    auto workspace = kasumi::platform::create_workspace_at(
        kasumi::test::workspace_root(owner) / "owned-workspace");
    ASSERT_TRUE(workspace) << workspace.error();
    const auto root = workspace->root;
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
        kasumi::platform::remove_workspace(*workspace);
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

TEST(PrivateStorageTest, CleanupRefusesToRemoveWhenInitialIdentityIsInvalid) {
    auto workspace =
        kasumi::test::make_temp_workspace("cleanup-invalid-initial-id");
    const auto file_path =
        kasumi::test::workspace_path(workspace, "victim.txt");
    kasumi::test::write_text(file_path, "important data");

    kasumi::platform::private_storage::PrivateOutputFile file{
        .handle = kasumi::platform::private_storage::invalid_private_handle,
        .path = file_path,
        .identity =
            kasumi::platform::private_storage::FileIdentity{.valid = false}};

    const auto result =
        kasumi::platform::private_storage::remove_private_file_if_owned(file);
    EXPECT_NE(result,
              kasumi::platform::private_storage::CleanupResult::Removed);
    EXPECT_TRUE(std::filesystem::exists(file_path));
    EXPECT_EQ(kasumi::test::read_text(file_path), "important data");
}

TEST(PrivateStorageTest,
     CleanupRefusesToRemoveWhenCurrentIdentityCannotBeQueried) {
    auto workspace =
        kasumi::test::make_temp_workspace("cleanup-unqueryable-current-id");
    const auto dir_path = kasumi::test::workspace_path(workspace, "victim_dir");
    std::filesystem::create_directory(dir_path);

    kasumi::platform::private_storage::PrivateOutputFile file{
        .handle = kasumi::platform::private_storage::invalid_private_handle,
        .path = dir_path,
        .identity = kasumi::platform::private_storage::FileIdentity{
            .volume_or_dev = 12345,
            .file_id_low = 67890,
            .file_id_high = 0,
            .valid = true}};

    const auto result =
        kasumi::platform::private_storage::remove_private_file_if_owned(file);
    EXPECT_NE(result,
              kasumi::platform::private_storage::CleanupResult::Removed);
    EXPECT_TRUE(std::filesystem::exists(dir_path));
}

TEST(PrivateStorageTest, CleanupReturnsAlreadyAbsentWhenFileTrulyDoesNotExist) {
    auto workspace = kasumi::test::make_temp_workspace("cleanup-truly-absent");
    const auto file_path =
        kasumi::test::workspace_path(workspace, "nonexistent.bin");

    kasumi::platform::private_storage::PrivateOutputFile file{
        .handle = kasumi::platform::private_storage::invalid_private_handle,
        .path = file_path,
        .identity =
            kasumi::platform::private_storage::FileIdentity{.valid = true}};

    const auto result =
        kasumi::platform::private_storage::remove_private_file_if_owned(file);
    EXPECT_EQ(result,
              kasumi::platform::private_storage::CleanupResult::AlreadyAbsent);
}

TEST(PrivateStorageTest, CleanupRepeatedCallReturnsAlreadyAbsent) {
    auto workspace = kasumi::test::make_temp_workspace("cleanup-repeated");
    const auto file_path =
        kasumi::test::workspace_path(workspace, "temp_to_remove.bin");

    auto created =
        kasumi::platform::private_storage::create_private_file(file_path);
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created->identity.valid);

    const auto first =
        kasumi::platform::private_storage::remove_private_file_if_owned(
            *created);
    EXPECT_EQ(first, kasumi::platform::private_storage::CleanupResult::Removed);
    EXPECT_FALSE(std::filesystem::exists(file_path));

    const auto second =
        kasumi::platform::private_storage::remove_private_file_if_owned(
            *created);
    EXPECT_EQ(second,
              kasumi::platform::private_storage::CleanupResult::AlreadyAbsent);
}

TEST(PrivateStorageTest, QueryIdentityRejectsDirectoriesAndReparsePoints) {
    auto workspace = kasumi::test::make_temp_workspace("query-identity-types");
    const auto dir_path = kasumi::test::workspace_path(workspace, "subdir");
    std::filesystem::create_directory(dir_path);

    const auto id =
        kasumi::platform::private_storage::query_file_identity(dir_path);
    EXPECT_FALSE(id.valid);
}

TEST(PrivateStorageTest, PrivateHandleMoveDoesNotLeakOrDoubleClose) {
    auto workspace =
        kasumi::test::make_temp_workspace("handle-ownership-transfer");
    const auto p1 = kasumi::test::workspace_path(workspace, "h1.bin");
    const auto p2 = kasumi::test::workspace_path(workspace, "h2.bin");

    auto f1 = kasumi::platform::private_storage::create_private_file(p1);
    auto f2 = kasumi::platform::private_storage::create_private_file(p2);
    ASSERT_TRUE(f1.has_value());
    ASSERT_TRUE(f2.has_value());

    const auto h1_raw = f1->handle.value;
    const auto h2_raw = f2->handle.value;
    ASSERT_NE(h1_raw,
              kasumi::platform::private_storage::invalid_private_handle);
    ASSERT_NE(h2_raw,
              kasumi::platform::private_storage::invalid_private_handle);

    // Overwriting f1 with f2 via move assignment must close f1's previous
    // handle (not leak it)
    *f1 = std::move(*f2);

    // 1. Source f2 is invalidated after transfer
    EXPECT_FALSE(f2->is_open());
    EXPECT_EQ(f2->handle.value,
              kasumi::platform::private_storage::invalid_private_handle);

    // 2. Target f1 owns h2_raw
    EXPECT_TRUE(f1->is_open());
    EXPECT_EQ(f1->handle.value, h2_raw);

    // 3. Previously held h1_raw was closed and NOT abandoned/leaked
#if defined(_WIN32)
    DWORD flags = 0;
    const BOOL h1_is_still_open =
        GetHandleInformation(reinterpret_cast<HANDLE>(h1_raw), &flags);
    EXPECT_FALSE(h1_is_still_open);
#else
    const int h1_status = ::fcntl(static_cast<int>(h1_raw), F_GETFD);
    EXPECT_EQ(h1_status, -1);
    EXPECT_EQ(errno, EBADF);
#endif

    // 4. Closing f1 closes h2_raw
    kasumi::platform::private_storage::close_private_file(*f1);
    EXPECT_FALSE(f1->is_open());

    // 5. Calling close_private_file again is a no-op (no double close)
    kasumi::platform::private_storage::close_private_file(*f1);
    kasumi::platform::private_storage::close_private_file(*f2);
}

TEST(PrivateStorageTest, PublicationRejectedWhenFileIdentityIsInvalid) {
    auto workspace = kasumi::test::make_temp_workspace("publish-invalid-id");
    const auto temp_path = kasumi::test::workspace_path(workspace, "temp.bin");
    const auto target_path =
        kasumi::test::workspace_path(workspace, "target.bin");

    auto f = kasumi::platform::private_storage::create_private_file(temp_path);
    ASSERT_TRUE(f.has_value());
    ASSERT_TRUE(f->is_open());

    f->identity.valid = false;
    auto pub_res = kasumi::platform::private_storage::publish_private_file(
        *f, target_path);
    EXPECT_FALSE(pub_res.has_value());
    EXPECT_FALSE(std::filesystem::exists(target_path));
}

TEST(PrivateStorageTest,
     SuccessfulPublicationTransfersOwnershipAndClosesHandle) {
    auto workspace = kasumi::test::make_temp_workspace("publish-ownership");
    const auto temp_path = kasumi::test::workspace_path(workspace, "temp.bin");
    const auto target_path =
        kasumi::test::workspace_path(workspace, "published_target.bin");

    auto f = kasumi::platform::private_storage::create_private_file(temp_path);
    ASSERT_TRUE(f.has_value());
    ASSERT_TRUE(f->is_open());

    const std::string payload = "authenticated durable plaintext";
    auto written = kasumi::platform::private_storage::write_private_file(
        *f, payload.data(), payload.size());
    ASSERT_TRUE(written.has_value());

    auto pub_res = kasumi::platform::private_storage::publish_private_file(
        *f, target_path);
    EXPECT_TRUE(pub_res.has_value());

    // Target contains the published authenticated plaintext
    EXPECT_TRUE(std::filesystem::exists(target_path));
    EXPECT_EQ(kasumi::test::read_text(target_path), payload);

    // Temporary path is gone (renamed)
    EXPECT_FALSE(std::filesystem::exists(temp_path));

    // Ownership was cleanly relinquished
    EXPECT_FALSE(f->is_open());
    EXPECT_TRUE(f->is_published());
    EXPECT_TRUE(f->path.empty());
    EXPECT_FALSE(f->identity.valid);

    // Subsequent cleanup call is a no-op returning AlreadyAbsent
    const auto cleanup_res =
        kasumi::platform::private_storage::remove_private_file_if_owned(*f);
    EXPECT_EQ(cleanup_res,
              kasumi::platform::private_storage::CleanupResult::AlreadyAbsent);
}

TEST(PrivateStorageTest,
     ExclusiveCreationDetectsCollisionAndPreservesFirstHandle) {
    auto workspace = kasumi::test::make_temp_workspace("create-collision");
    const auto file_path =
        kasumi::test::workspace_path(workspace, "exclusive.bin");

    // 1. Criar um temporário exclusivo.
    auto f1 = kasumi::platform::private_storage::create_private_file(file_path);
    ASSERT_TRUE(f1.has_value());
    ASSERT_TRUE(f1->is_open());

    const std::string payload = "original content";
    auto write_res = kasumi::platform::private_storage::write_private_file(
        *f1, payload.data(), payload.size());
    ASSERT_TRUE(write_res.has_value());

    // 2. Tentar criá-lo novamente.
    auto f2 = kasumi::platform::private_storage::create_private_file(file_path);

    // 3. Confirmar que a segunda tentativa falha.
    ASSERT_FALSE(f2.has_value());

    // 4. Confirmar is_collision == true.
    EXPECT_TRUE(f2.error().is_collision);

    // 5. Confirmar que o conteúdo e o handle da primeira operação permanecem válidos.
    EXPECT_TRUE(f1->is_open());
    kasumi::platform::private_storage::close_private_file(*f1);
    EXPECT_EQ(kasumi::test::read_text(file_path), payload);

    // 6. Confirmar que erro por diretório inexistente tem is_collision == false.
    const auto invalid_path =
        kasumi::test::workspace_path(workspace, "nonexistent_dir/file.bin");
    auto f3 =
        kasumi::platform::private_storage::create_private_file(invalid_path);
    ASSERT_FALSE(f3.has_value());
    EXPECT_FALSE(f3.error().is_collision);
}

TEST(PrivateStorageTest, FlushAndCloseReleasesHandleAndPreservesContent) {
    auto workspace = kasumi::test::make_temp_workspace("flush-close-basic");
    const auto file_path = kasumi::test::workspace_path(workspace, "flush.bin");

    // 1. Criar um arquivo privado em workspace descartável.
    auto file = kasumi::platform::private_storage::create_private_file(file_path);
    ASSERT_TRUE(file.has_value());

    // 2. Confirmar que o handle está aberto.
    EXPECT_TRUE(file->is_open());
    const auto raw_handle = file->handle.value;
    EXPECT_NE(raw_handle,
              kasumi::platform::private_storage::invalid_private_handle);

    // 3. Escrever um payload conhecido.
    const std::string payload = "flush and close payload verification";
    auto write_res = kasumi::platform::private_storage::write_private_file(
        *file, payload.data(), payload.size());
    ASSERT_TRUE(write_res.has_value());

    // 4. Executar flush_and_close_private_file().
    auto flush_res =
        kasumi::platform::private_storage::flush_and_close_private_file(*file);

    // 5. Confirmar sucesso.
    EXPECT_TRUE(flush_res.has_value());

    // 6. Confirmar is_open() == false.
    EXPECT_FALSE(file->is_open());

    // 7. Confirmar handle.value == invalid_private_handle.
    EXPECT_EQ(file->handle.value,
              kasumi::platform::private_storage::invalid_private_handle);

    // 8. Confirmar que os bytes gravados permanecem íntegros.
    EXPECT_EQ(kasumi::test::read_text(file_path), payload);

    // 9. Executar close_private_file() novamente.
    kasumi::platform::private_storage::close_private_file(*file);

    // 10. Confirmar que a operação não destrói outro recurso.
    EXPECT_FALSE(file->is_open());
    EXPECT_EQ(file->handle.value,
              kasumi::platform::private_storage::invalid_private_handle);
}

TEST(PrivateStorageTest, FlushAndCloseRepeatedCallIsNoOp) {
    auto workspace = kasumi::test::make_temp_workspace("flush-close-repeat");
    const auto file_path = kasumi::test::workspace_path(workspace, "repeat.bin");

    auto file = kasumi::platform::private_storage::create_private_file(file_path);
    ASSERT_TRUE(file.has_value());
    EXPECT_TRUE(file->is_open());

    const std::string payload = "repeat call preservation test";
    auto write_res = kasumi::platform::private_storage::write_private_file(
        *file, payload.data(), payload.size());
    ASSERT_TRUE(write_res.has_value());

    // Primeiro flush e fechamento bem-sucedidos.
    auto first_res =
        kasumi::platform::private_storage::flush_and_close_private_file(*file);
    EXPECT_TRUE(first_res.has_value());
    EXPECT_FALSE(file->is_open());
    EXPECT_EQ(file->handle.value,
              kasumi::platform::private_storage::invalid_private_handle);

    // Segunda chamada não tenta utilizar handle inválido e retorna sucesso (no-op).
    auto second_res =
        kasumi::platform::private_storage::flush_and_close_private_file(*file);
    EXPECT_TRUE(second_res.has_value());
    EXPECT_FALSE(file->is_open());

    // close_private_file() posterior permanece inofensivo.
    kasumi::platform::private_storage::close_private_file(*file);
    EXPECT_FALSE(file->is_open());

    // Conteúdo do arquivo permanece íntegro.
    EXPECT_EQ(kasumi::test::read_text(file_path), payload);
}

} // namespace
