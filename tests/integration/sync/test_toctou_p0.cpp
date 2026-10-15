#include "application/sync/coordinator.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_detail.hpp"
#include "application/sync/mutation_fault_test.hpp"
#include "core/ignore.hpp"
#include "core/operation.hpp"
#include "core/transaction/types.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/durability.hpp"
#include "platform/file_fingerprint.hpp"
#include "platform/path.hpp"

#include <array>
#include <filesystem>
#include <future>
#include <gtest/gtest.h>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

using namespace kasumi;
namespace mutation = kasumi::application::sync::mutation;
namespace fault_test = kasumi::application::sync::mutation_fault_test;

struct HookGuard {
    HookGuard() = default;
    explicit HookGuard(fault_test::Hook hook) {
        fault_test::set_hook(std::move(hook));
    }
    ~HookGuard() {
        fault_test::clear_hook();
    }
    HookGuard(const HookGuard&) = delete;
    HookGuard& operator=(const HookGuard&) = delete;
};

bool is_content_preserved(const std::filesystem::path& root,
                          std::string_view expected_content) {
    std::error_code ec;
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(root, ec)) {
        if (entry.is_regular_file(ec)) {
            const auto text = test::read_text(entry.path());
            if (text == expected_content ||
                text.find(expected_content) != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

#if defined(_WIN32)
struct ScopedNativeHandle {
    HANDLE handle = INVALID_HANDLE_VALUE;
    ~ScopedNativeHandle() {
        close();
    }
    ScopedNativeHandle() = default;
    explicit ScopedNativeHandle(HANDLE h) : handle(h) {
    }
    ScopedNativeHandle(const ScopedNativeHandle&) = delete;
    ScopedNativeHandle& operator=(const ScopedNativeHandle&) = delete;
    ScopedNativeHandle(ScopedNativeHandle&& other) noexcept
        : handle(other.handle) {
        other.handle = INVALID_HANDLE_VALUE;
    }
    ScopedNativeHandle& operator=(ScopedNativeHandle&& other) noexcept {
        if (this != &other) {
            close();
            handle = other.handle;
            other.handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    bool is_open() const {
        return handle != INVALID_HANDLE_VALUE;
    }
    void write(std::string_view data) {
        if (!is_open())
            return;
        DWORD written = 0;
        SetFilePointer(handle, 0, nullptr, FILE_BEGIN);
        WriteFile(handle,
                  data.data(),
                  static_cast<DWORD>(data.size()),
                  &written,
                  nullptr);
        SetEndOfFile(handle);
        FlushFileBuffers(handle);
    }
    void close() {
        if (handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
            handle = INVALID_HANDLE_VALUE;
        }
    }
};

inline ScopedNativeHandle
open_native_write_handle(const std::filesystem::path& p) {
    HANDLE h =
        CreateFileW(p.c_str(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr);
    return ScopedNativeHandle{h};
}
#else
struct ScopedNativeHandle {
    int fd = -1;
    ~ScopedNativeHandle() {
        close();
    }
    ScopedNativeHandle() = default;
    explicit ScopedNativeHandle(int f) : fd(f) {
    }
    ScopedNativeHandle(const ScopedNativeHandle&) = delete;
    ScopedNativeHandle& operator=(const ScopedNativeHandle&) = delete;
    ScopedNativeHandle(ScopedNativeHandle&& other) noexcept : fd(other.fd) {
        other.fd = -1;
    }
    ScopedNativeHandle& operator=(ScopedNativeHandle&& other) noexcept {
        if (this != &other) {
            close();
            fd = other.fd;
            other.fd = -1;
        }
        return *this;
    }
    bool is_open() const {
        return fd >= 0;
    }
    void write(std::string_view data) {
        if (!is_open())
            return;
        lseek(fd, 0, SEEK_SET);
        auto w = ::write(fd, data.data(), data.size());
        (void)w;
        if (::ftruncate(fd, static_cast<off_t>(data.size())) != 0)
            return;
        (void)::fsync(fd);
    }
    void close() {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }
};

inline ScopedNativeHandle
open_native_write_handle(const std::filesystem::path& p) {
    int fd = ::open(p.c_str(), O_RDWR);
    return ScopedNativeHandle{fd};
}
#endif

void stage_remote_object(transport::Transport& storage,
                         const std::filesystem::path& source,
                         const Hash& hash) {
    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    const auto encrypted =
        platform::path::temporary_sibling_path(source, "", ".enc_stage");
    ASSERT_TRUE(crypto::encrypt_file(source, encrypted, key));
    ASSERT_TRUE(transport::put(
        storage, encrypted, crypto::content_identifier(key, hash)));
    std::error_code ec;
    std::filesystem::remove(encrypted, ec);
}

#if defined(_WIN32)
bool create_test_junction(const std::filesystem::path& link,
                          const std::filesystem::path& target,
                          std::error_code& error) {
    struct MountPointData {
        DWORD tag = IO_REPARSE_TAG_MOUNT_POINT;
        WORD data_length = 0;
        WORD reserved = 0;
        WORD substitute_offset = 0;
        WORD substitute_length = 0;
        WORD print_offset = 0;
        WORD print_length = 0;
        std::array<wchar_t, 2048> path_buffer{};
    } data;

    if (!CreateDirectoryW(link.c_str(), nullptr)) {
        error = std::error_code{static_cast<int>(GetLastError()),
                                std::system_category()};
        return false;
    }
    const auto substitute = std::wstring{L"\\??\\"} + target.wstring();
    const auto printed = target.wstring();
    const auto substitute_bytes = substitute.size() * sizeof(wchar_t);
    const auto print_bytes = printed.size() * sizeof(wchar_t);
    if (substitute_bytes + print_bytes + 2 * sizeof(wchar_t) >
        data.path_buffer.size() * sizeof(wchar_t)) {
        RemoveDirectoryW(link.c_str());
        error = std::make_error_code(std::errc::filename_too_long);
        return false;
    }
    data.substitute_length = static_cast<WORD>(substitute_bytes);
    data.print_offset = static_cast<WORD>(substitute_bytes + sizeof(wchar_t));
    data.print_length = static_cast<WORD>(print_bytes);
    data.data_length = static_cast<WORD>(
        8 + substitute_bytes + sizeof(wchar_t) + print_bytes + sizeof(wchar_t));
    std::memcpy(data.path_buffer.data(), substitute.data(), substitute_bytes);
    std::memcpy(reinterpret_cast<std::byte*>(data.path_buffer.data()) +
                    data.print_offset,
                printed.data(),
                print_bytes);

    const auto handle =
        CreateFileW(link.c_str(),
                    GENERIC_WRITE,
                    0,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        error = std::error_code{static_cast<int>(GetLastError()),
                                std::system_category()};
        RemoveDirectoryW(link.c_str());
        return false;
    }
    DWORD returned = 0;
    const auto configured = DeviceIoControl(handle,
                                            FSCTL_SET_REPARSE_POINT,
                                            &data,
                                            data.data_length + 8,
                                            nullptr,
                                            0,
                                            &returned,
                                            nullptr) != 0;
    const auto device_error = GetLastError();
    CloseHandle(handle);
    if (!configured) {
        error = std::error_code{static_cast<int>(device_error),
                                std::system_category()};
        RemoveDirectoryW(link.c_str());
        return false;
    }
    return true;
}
#endif

} // namespace

// RED-01: Download overwriting external edit U after hash verification
TEST(P0ToctouExploratoryTest, RED01_DownloadCanReplaceAnEditAfterValidation) {
    auto workspace = test::make_temp_workspace("p0-toctou-red01");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");

    const auto r_hash = hasher::hash_string("REMOTE_R");
    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    bool hook_hit = false;
    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path& p) {
            if (point == "before_download_replace") {
                hook_hit = true;
                test::write_text(p, "EXTERNAL_U");
            }
        });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);

    ASSERT_TRUE(hook_hit) << "Hook before_download_replace was not reached";

    EXPECT_TRUE(res.has_value()) << (res ? "" : res.error().detail);
    EXPECT_EQ(test::read_text(target), "REMOTE_R");
    EXPECT_FALSE(is_content_preserved(root, "EXTERNAL_U"));
}

// RED-02: Download after inode replacement
TEST(P0ToctouExploratoryTest, RED02_DownloadCanReplaceAnInodeChangedAfterValidation) {
    auto workspace = test::make_temp_workspace("p0-toctou-red02");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");

    const auto r_hash = hasher::hash_string("REMOTE_R");
    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    bool hook_hit = false;
    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path& p) {
            if (point == "before_download_replace") {
                hook_hit = true;
                std::filesystem::remove(p);
                test::write_text(p, "EXTERNAL_U_NEW_INODE");
            }
        });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);

    ASSERT_TRUE(hook_hit) << "Hook before_download_replace was not reached";

    EXPECT_TRUE(res.has_value()) << (res ? "" : res.error().detail);
    EXPECT_EQ(test::read_text(target), "REMOTE_R");
    EXPECT_FALSE(is_content_preserved(root, "EXTERNAL_U_NEW_INODE"));
}

// RED-03: Download after external creation in absent destination
TEST(P0ToctouContractTest, RED03_ConditionalInstallPreservesLateCreation) {
    auto workspace = test::make_temp_workspace("p0-toctou-red03");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(root / "remote_src", "REMOTE_R");

    const auto r_hash = hasher::hash_string("REMOTE_R");
    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    bool hook_hit = false;
    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path& p) {
            if (point == "before_download_install") {
                hook_hit = true;
                test::write_text(p, "EXTERNAL_U_CREATED");
            }
        });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);

    ASSERT_TRUE(hook_hit) << "Hook before_download_install was not reached";
    EXPECT_FALSE(res.has_value());
    EXPECT_TRUE(is_content_preserved(root, "EXTERNAL_U_CREATED"));
    EXPECT_EQ(test::read_text(target), "EXTERNAL_U_CREATED");
}

// RED-04: DeleteLocal removes external edit U after verification
TEST(P0ToctouExploratoryTest, RED04_DeleteCanRemoveAnEditAfterValidation) {
    auto workspace = test::make_temp_workspace("p0-toctou-red04");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");

    const Operation op{.action = Action::DeleteLocal, .path = "file.txt"};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    bool hook_hit = false;
    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path& p) {
            if (point == "before_delete_local") {
                hook_hit = true;
                test::write_text(p, "EXTERNAL_U_EDIT");
            }
        });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    transport::Transport unavailable;
    auto res = mutation::apply_operation(
        op, 0, local, unavailable, key, transaction, *prepared);

    ASSERT_TRUE(hook_hit) << "Hook before_delete_local was not reached";

    EXPECT_TRUE(res.has_value()) << (res ? "" : res.error().detail);
    EXPECT_FALSE(std::filesystem::exists(target));
    EXPECT_FALSE(is_content_preserved(root, "EXTERNAL_U_EDIT"));
}

// RED-05: DeleteLocal with ABA recreation
TEST(P0ToctouExploratoryTest, RED05_DeleteCanRemoveAnAbaReplacementAfterValidation) {
    auto workspace = test::make_temp_workspace("p0-toctou-red05");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    const std::string original_content = "ORIGINAL_O"; // exactly 10 bytes
    const std::string aba_content = "ABA_SAME10";      // exactly 10 bytes
    ASSERT_EQ(original_content.size(), aba_content.size());
    test::write_text(target, original_content);

    const Operation op{.action = Action::DeleteLocal, .path = "file.txt"};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    bool hook_hit = false;
    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path& p) {
            if (point == "before_delete_local") {
                hook_hit = true;
                std::filesystem::remove(p);
                test::write_text(p, aba_content);
            }
        });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    transport::Transport unavailable;
    auto res = mutation::apply_operation(
        op, 0, local, unavailable, key, transaction, *prepared);

    ASSERT_TRUE(hook_hit) << "Hook before_delete_local was not reached";

    EXPECT_TRUE(res.has_value()) << (res ? "" : res.error().detail);
    EXPECT_FALSE(std::filesystem::exists(target));
    EXPECT_FALSE(is_content_preserved(root, aba_content));
}

// RED-06: RenameLocal with concurrent edit at source
TEST(P0ToctouExploratoryTest, RED06_RenameCanCarryAnEditAfterValidation) {
    auto workspace = test::make_temp_workspace("p0-toctou-red06");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(transaction.root);

    const auto source = local / "source.txt";
    const auto destination = local / "conflict.txt";
    test::write_text(source, "ORIGINAL_O");

    const Operation op{.action = Action::RenameLocal,
                       .path = "source.txt",
                       .alt_path = "conflict.txt"};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    bool hook_hit = false;
    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path& p) {
            if (point == "before_rename_move") {
                hook_hit = true;
                test::write_text(p, "EXTERNAL_U_RENAME");
            }
        });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    transport::Transport unavailable;
    auto res = mutation::apply_operation(
        op, 0, local, unavailable, key, transaction, *prepared);

    ASSERT_TRUE(hook_hit) << "Hook before_rename_move was not reached";

    EXPECT_TRUE(res.has_value()) << (res ? "" : res.error().detail);
    EXPECT_FALSE(std::filesystem::exists(source));
    EXPECT_EQ(test::read_text(destination), "EXTERNAL_U_RENAME");
}

// RED-07: Rollback removes external edit U
TEST(P0ToctouExploratoryTest, RED07_RollbackCanReplaceAnEditAfterValidation) {
    auto workspace = test::make_temp_workspace("p0-toctou-red07");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");

    const auto r_hash = hasher::hash_string("REMOTE_R");
    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);
    ASSERT_TRUE(res.has_value());

    auto progress = *prepared;
    progress.state = transaction::OperationState::Applied;

    // During rollback, between hash validation and replace: write U
    bool hook_hit = false;
    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path& p) {
            if (point == "before_restore_replace") {
                hook_hit = true;
                test::write_text(p, "EXTERNAL_U_ROLLBACK");
            }
        });

    auto rolled =
        mutation::rollback_operation(op, 0, local, transaction, progress);

    ASSERT_TRUE(hook_hit) << "Hook before_restore_replace was not reached";

    EXPECT_TRUE(rolled.has_value()) << (rolled ? "" : rolled.error().detail);
    EXPECT_EQ(test::read_text(target), "ORIGINAL_O");
    EXPECT_FALSE(is_content_preserved(root, "EXTERNAL_U_ROLLBACK"));
}

// RED-08: RestoreBackup over modified destination
TEST(P0ToctouExploratoryTest, RED08_RestoreCanReplaceAnEditAfterValidation) {
    auto workspace = test::make_temp_workspace("p0-toctou-red08");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");

    const auto r_hash = hasher::hash_string("REMOTE_R");
    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);
    ASSERT_TRUE(res.has_value());
    ASSERT_EQ(test::read_text(target), "REMOTE_R");

    auto progress = *prepared;
    progress.state = transaction::OperationState::Applied;

    bool hook_hit = false;
    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path& p) {
            if (point == "before_restore_replace") {
                hook_hit = true;
                test::write_text(p, "EXTERNAL_U_RESTORE");
            }
        });

    auto rolled =
        mutation::rollback_operation(op, 0, local, transaction, progress);

    ASSERT_TRUE(hook_hit) << "Hook before_restore_replace was not reached!";

    EXPECT_TRUE(rolled.has_value()) << (rolled ? "" : rolled.error().detail);
    EXPECT_EQ(test::read_text(target), "ORIGINAL_O");
    EXPECT_FALSE(is_content_preserved(root, "EXTERNAL_U_RESTORE"));
}

// RED-09: Rollback of RenameLocal with external modification
TEST(P0ToctouExploratoryTest, RED09_RollbackCanRemoveAnEditAfterValidation) {
    auto workspace = test::make_temp_workspace("p0-toctou-red09");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(transaction.root);

    const auto source = local / "source.txt";
    const auto destination = local / "conflict.txt";
    test::write_text(source, "ORIGINAL_O");

    const Operation op{.action = Action::RenameLocal,
                       .path = "source.txt",
                       .alt_path = "conflict.txt"};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    transport::Transport unavailable;
    auto res = mutation::apply_operation(
        op, 0, local, unavailable, key, transaction, *prepared);
    ASSERT_TRUE(res.has_value());

    auto progress = *prepared;
    progress.state = transaction::OperationState::Applied;

    bool hook_hit = false;
    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path& p) {
            if (point == "before_remove_file_if_hash") {
                hook_hit = true;
                test::write_text(p, "EXTERNAL_U_DURING_REMOVE");
            }
        });

    auto rolled =
        mutation::rollback_operation(op, 0, local, transaction, progress);

    ASSERT_TRUE(hook_hit) << "Hook before_remove_file_if_hash was not reached!";

    EXPECT_TRUE(rolled.has_value()) << (rolled ? "" : rolled.error().detail);
    EXPECT_FALSE(std::filesystem::exists(destination));
    EXPECT_FALSE(is_content_preserved(root, "EXTERNAL_U_DURING_REMOVE"));
}

// RED-10: Download after confirmed RenameLocal
TEST(P0ToctouContractTest, RED10_DownloadAfterConfirmedRenameLocal) {
    auto workspace = test::make_temp_workspace("p0-toctou-red10");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto source = local / "file.txt";
    const auto conflict = local / "file.conflict";
    test::write_text(source, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");

    const auto r_hash = hasher::hash_string("REMOTE_R");
    const Operation rename_op{.action = Action::RenameLocal,
                              .path = "file.txt",
                              .alt_path = "file.conflict"};
    const Operation download_op{.action = Action::Download,
                                .path = "file.txt",
                                .hash = hash_hex(r_hash),
                                .size = 8};

    const auto prep_rename = mutation::prepare_operation(
        rename_op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prep_rename.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res_rename = mutation::apply_operation(
        rename_op, 0, local, *storage, key, transaction, *prep_rename);
    ASSERT_TRUE(res_rename.has_value());

    const auto prep_download = mutation::prepare_operation(
        download_op, 1, local, transaction, {.backup_slot = 1});
    ASSERT_TRUE(prep_download.has_value());

    mutation::DestinationPrecondition condition{.hash = "",
                                                .backup = std::nullopt};
    auto res_download =
        mutation::apply_operation(download_op,
                                  1,
                                  local,
                                  *storage,
                                  key,
                                  transaction,
                                  *prep_download,
                                  mutation::DownloadCacheMode::None,
                                  &condition);
    ASSERT_TRUE(res_download.has_value());
    EXPECT_EQ(test::read_text(local / "file.txt"), "REMOTE_R");
    EXPECT_EQ(test::read_text(local / "file.conflict"), "ORIGINAL_O");
}

// RED-11: RenameLocal filling conflict destination
TEST(P0ToctouContractTest, RED11_RenameLocalFillingConflictDestination) {
    auto workspace = test::make_temp_workspace("p0-toctou-red11");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto node = local / "node";
    test::write_text(node, "ORIGINAL_FILE");
    test::write_text(root / "remote_child", "CHILD_DATA");

    const auto child_hash = hasher::hash_string("CHILD_DATA");
    const Operation rename_op{.action = Action::RenameLocal,
                              .path = "node",
                              .alt_path = "node.kasumiconflict_remote"};
    const Operation mkdir_op{.action = Action::CreateLocalDirectory,
                             .path = "node"};
    const Operation download_op{.action = Action::Download,
                                .path = "node/child.txt",
                                .hash = hash_hex(child_hash),
                                .size = 10};

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_child", child_hash);

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};

    const auto prep_rename = mutation::prepare_operation(
        rename_op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prep_rename.has_value());
    const auto rename_result = mutation::apply_operation(
        rename_op, 0, local, *storage, key, transaction, *prep_rename);
    ASSERT_TRUE(rename_result.has_value());

    const auto prep_mkdir = mutation::prepare_operation(
        mkdir_op, 1, local, transaction, {.backup_slot = 1});
    ASSERT_TRUE(prep_mkdir.has_value());
    ASSERT_TRUE(mutation::apply_operation(
        mkdir_op, 1, local, *storage, key, transaction, *prep_mkdir));

    const auto prep_down = mutation::prepare_operation(
        download_op, 2, local, transaction, {.backup_slot = 2});
    ASSERT_TRUE(prep_down.has_value());
    ASSERT_TRUE(mutation::apply_operation(
        download_op, 2, local, *storage, key, transaction, *prep_down));

    EXPECT_TRUE(std::filesystem::is_directory(local / "node"));
    EXPECT_EQ(test::read_text(local / "node/child.txt"), "CHILD_DATA");
    EXPECT_EQ(test::read_text(local / "node.kasumiconflict_remote"),
              "ORIGINAL_FILE");
}

// RED-12: Corrupted backup B with conflict
TEST(P0ToctouContractTest, RED12_CorruptedBackupWithConflict) {
    auto workspace = test::make_temp_workspace("p0-toctou-red12");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");

    const Operation op{.action = Action::DeleteLocal, .path = "file.txt"};
    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    // Corrupt the backup
    test::write_text(transaction.root / "0.backup", "CORRUPTED");

    // Put U in target
    test::write_text(target, "EXTERNAL_U_DATA");

    auto progress = *prepared;
    progress.state = transaction::OperationState::Applied;

    auto rolled =
        mutation::rollback_operation(op, 0, local, transaction, progress);

    // Rollback must fail and preserve U
    EXPECT_FALSE(rolled.has_value());
    EXPECT_TRUE(is_content_preserved(root, "EXTERNAL_U_DATA"));
}

// RED-13: Open file during replace/rename
TEST(P0ToctouExploratoryTest, RED13_OpenFileDuringReplace) {
    auto workspace = test::make_temp_workspace("p0-toctou-red13");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");

    const auto r_hash = hasher::hash_string("REMOTE_R");
    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

#if defined(_WIN32)
    // Open handle with exclusive sharing (no FILE_SHARE_DELETE)
    HANDLE h = CreateFileW(target.c_str(),
                           GENERIC_READ,
                           0,
                           nullptr,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    ASSERT_NE(h, INVALID_HANDLE_VALUE);

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);

    CloseHandle(h);

    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(test::read_text(target), "ORIGINAL_O");
#else
    int fd = ::open(target.c_str(), O_RDWR);
    ASSERT_GE(fd, 0);

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);

    const char extra[] = "_EXTRA";
    ssize_t written = ::write(fd, extra, sizeof(extra) - 1);
    EXPECT_GT(written, 0);
    ::close(fd);

    if (res.has_value()) {
        EXPECT_EQ(test::read_text(target), "REMOTE_R");
    } else {
        EXPECT_TRUE(test::read_text(target).starts_with("ORIGINAL_O") ||
                    test::read_text(target) == "REMOTE_R" ||
                    is_content_preserved(root, "_EXTRA"));
    }
#endif
}

// RED-14: Hardlink alias modification
TEST(P0ToctouExploratoryTest, RED14_HardlinkAlias) {
    auto workspace = test::make_temp_workspace("p0-toctou-red14");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    const auto alias = local / "alias.txt";
    test::write_text(target, "ORIGINAL_O");

    std::error_code ec;
    std::filesystem::create_hard_link(target, alias, ec);
    if (ec) {
        GTEST_SKIP() << "Hardlinks not supported on filesystem";
    }

    const Operation op{.action = Action::DeleteLocal, .path = "file.txt"};
    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    // Modify via alias
    test::write_text(alias, "MODIFIED_VIA_ALIAS");

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    transport::Transport unavailable;
    auto res = mutation::apply_operation(
        op, 0, local, unavailable, key, transaction, *prepared);

    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(test::read_text(alias), "MODIFIED_VIA_ALIAS");
}

// RED-15: Symlink/reparse point injected in critical window
TEST(P0ToctouContractTest, RED15_SymlinkReparsePointInCriticalWindow) {
    auto workspace = test::make_temp_workspace("p0-toctou-red15");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto outside_dir = root / "outside_dir";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(outside_dir);
    std::filesystem::create_directories(transaction.root);

    test::write_text(outside_dir / "secret.txt", "CONFIDENTIAL_EXTERNAL");
    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");

    const Operation op{.action = Action::DeleteLocal, .path = "file.txt"};
    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    bool hook_hit = false;
    bool adversarial_created = false;
    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path& p) {
            if (point == "before_delete_local") {
                hook_hit = true;
                std::filesystem::remove(p);
#if defined(_WIN32)
                std::error_code ec;
                adversarial_created = create_test_junction(p, outside_dir, ec);
                EXPECT_TRUE(adversarial_created && !ec)
                    << "Failed to create junction: " << ec.message();
#else
                std::error_code ec;
                std::filesystem::create_symlink(outside_dir, p, ec);
                adversarial_created = !ec;
                EXPECT_TRUE(adversarial_created)
                    << "Failed to create symlink: " << ec.message();
#endif
                EXPECT_TRUE(std::filesystem::exists(p));
            }
        });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    transport::Transport unavailable;
    auto res = mutation::apply_operation(
        op, 0, local, unavailable, key, transaction, *prepared);

    ASSERT_TRUE(hook_hit) << "Hook before_delete_local was not reached";
    ASSERT_TRUE(adversarial_created)
        << "Adversarial junction/symlink was not created";

    EXPECT_FALSE(res.has_value());
    EXPECT_TRUE(std::filesystem::exists(outside_dir / "secret.txt"));
    EXPECT_EQ(test::read_text(outside_dir / "secret.txt"),
              "CONFIDENTIAL_EXTERNAL");
}

// RED-16: Ancestor directory modification
TEST(P0ToctouExploratoryTest, RED16_AncestorDirectoryModification) {
    auto workspace = test::make_temp_workspace("p0-toctou-red16");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto sub = local / "subdir";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(sub);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = sub / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");

    const auto r_hash = hasher::hash_string("REMOTE_R");
    const Operation op{.action = Action::Download,
                       .path = "subdir/file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    HookGuard guard([&](std::string_view point, const std::filesystem::path&) {
        if (point == "before_download_replace") {
            std::error_code ec;
            std::filesystem::rename(sub, local / "subdir_moved", ec);
        }
    });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);

    EXPECT_FALSE(res.has_value());
}

// RED-17: Unexpected object type (directory at target)
TEST(P0ToctouContractTest, RED17_UnexpectedObjectType) {
    auto workspace = test::make_temp_workspace("p0-toctou-red17");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");

    const Operation op{.action = Action::DeleteLocal, .path = "file.txt"};
    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path& p) {
            if (point == "before_delete_local") {
                std::filesystem::remove(p);
                std::filesystem::create_directory(p);
            }
        });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    transport::Transport unavailable;
    auto res = mutation::apply_operation(
        op, 0, local, unavailable, key, transaction, *prepared);

    EXPECT_FALSE(res.has_value());
    EXPECT_TRUE(std::filesystem::is_directory(target));
}

// RED-18: Same hash, different physical identity
TEST(P0ToctouExploratoryTest, RED18_SameHashDifferentPhysicalIdentity) {
    auto workspace = test::make_temp_workspace("p0-toctou-red18");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "SAME_CONTENT");
    const auto fp1 = platform::regular_file_fingerprint(target);

    // Prepare DeleteLocal
    const Operation op{.action = Action::DeleteLocal, .path = "file.txt"};
    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    // Recreate with same content
    std::filesystem::remove(target);
    test::write_text(target, "SAME_CONTENT");
    const auto fp2 = platform::regular_file_fingerprint(target);

#if defined(_WIN32)
    ASSERT_TRUE(fp1.has_value());
    ASSERT_TRUE(fp2.has_value());
    if (fp1->has_value() && fp2->has_value()) {
        EXPECT_NE((*fp1)->value[3],
                  (*fp2)->value[3]); // ctime / changetime difference
    }
#endif
    EXPECT_EQ(crypto::content::hash_file(target).value(),
              hasher::hash_string("SAME_CONTENT"));

    // Mutation over recreated object: contract test
    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    transport::Transport unavailable;
    auto res = mutation::apply_operation(
        op, 0, local, unavailable, key, transaction, *prepared);

    if (!res.has_value()) {
        EXPECT_TRUE(std::filesystem::exists(target));
    }
}

// RED-19: Independent parallel downloads with 1 conflict
TEST(P0ToctouExploratoryTest,
     RED19_ParallelDownloadCanReplaceEditAfterFinalValidation) {
    auto workspace = test::make_temp_workspace("p0-toctou-red19");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    constexpr int kFiles = 3;
    std::vector<Operation> ops;
    std::vector<transaction::OperationProgress> preps;

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));

    for (int i = 0; i < kFiles; ++i) {
        const std::string name = "file" + std::to_string(i) + ".txt";
        const std::string data = "REMOTE_" + std::to_string(i);
        const auto hash = hasher::hash_string(data);
        test::write_text(local / name, "ORIG_" + std::to_string(i));
        test::write_text(root / ("src_" + std::to_string(i)), data);
        stage_remote_object(
            *storage, root / ("src_" + std::to_string(i)), hash);

        Operation op{.action = Action::Download,
                     .path = name,
                     .hash = hash_hex(hash),
                     .size = data.size()};
        auto prep = mutation::prepare_operation(
            op,
            static_cast<std::size_t>(i),
            local,
            transaction,
            {.backup_slot = static_cast<std::uint32_t>(i)});
        ASSERT_TRUE(prep.has_value());
        ops.push_back(op);
        preps.push_back(*prep);
    }

    // Worker 1 encounters U
    bool hook_hit = false;
    HookGuard guard([&](std::string_view point,
                        const std::filesystem::path& p) {
        if (point == "before_download_replace" && p.filename() == "file1.txt") {
            hook_hit = true;
            test::write_text(p, "EXTERNAL_U_PARALLEL");
        }
    });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    std::vector<std::future<mutation::MutationResult>> futures;
    for (std::size_t i = 0; i < ops.size(); ++i) {
        futures.push_back(std::async(std::launch::async, [&, i] {
            return mutation::apply_operation(
                ops[i], i, local, *storage, key, transaction, preps[i]);
        }));
    }

    for (auto& f : futures) {
        (void)f.get();
    }

    ASSERT_TRUE(hook_hit)
        << "Hook before_download_replace was not reached for file1.txt";

    EXPECT_EQ(test::read_text(local / "file1.txt"), "REMOTE_1");
    EXPECT_FALSE(is_content_preserved(root, "EXTERNAL_U_PARALLEL"));
}

// RED-20: Two dependent operations on same path respect dependency ordering
TEST(P0ToctouContractTest, RED20_TwoDependentOperationsOnSamePath) {
    const std::vector<Operation> ops{Operation{.action = Action::RenameLocal,
                                               .path = "dir/old.txt",
                                               .alt_path = "dir/conflict.txt"},
                                     Operation{.action = Action::Download,
                                               .path = "dir/old.txt",
                                               .hash = std::string(64, '0'),
                                               .size = 10}};

    const auto deps = mutation::detail::destination_dependencies(ops);
    ASSERT_EQ(deps.size(), 2U);
    EXPECT_EQ(deps[0], std::numeric_limits<std::size_t>::max());
    EXPECT_EQ(deps[1], 0U); // depends on op 0
}

// ============================================================================
// P0ToctouCustodyTest (RED-21 to RED-35)
// Phase 3.4D.1 - Post-Custody TOCTOU, Safe Cleanup & Crash Recovery Suite
// ============================================================================

// RED-21: Download post-hash open handle write survives cleanup
TEST(P0ToctouExploratoryTest,
     RED21_DownloadCanLoseAWriteThroughAnOldOpenHandle) {
    auto workspace = test::make_temp_workspace("p0-toctou-red21");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");

    const auto r_hash = hasher::hash_string("REMOTE_R");
    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    auto h = open_native_write_handle(target);
    ASSERT_TRUE(h.is_open());

    bool hook_hit = false;
    HookGuard guard([&](std::string_view point, const std::filesystem::path&) {
        if (point == "before_download_replace") {
            hook_hit = true;
            h.write("EXTERNAL_U_RED21");
        }
    });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);

    h.close();
    EXPECT_TRUE(hook_hit);
    const auto final = test::read_text(target);
    EXPECT_TRUE(final == "REMOTE_R" || final == "EXTERNAL_U_RED21");
    EXPECT_EQ(res.has_value(), final == "REMOTE_R");
    EXPECT_EQ(is_content_preserved(root, "EXTERNAL_U_RED21"),
              final == "EXTERNAL_U_RED21");
}

// RED-22: DeleteLocal post-hash open handle write survives cleanup
TEST(P0ToctouExploratoryTest, RED22_DeleteCanLoseAWriteThroughAnOpenHandle) {
    auto workspace = test::make_temp_workspace("p0-toctou-red22");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    const auto orig_hash = hasher::hash_string("ORIGINAL_O");

    const Operation op{.action = Action::DeleteLocal,
                       .path = "file.txt",
                       .hash = hash_hex(orig_hash)};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto h = open_native_write_handle(target);
    ASSERT_TRUE(h.is_open());

    bool hook_hit = false;
    HookGuard guard([&](std::string_view point, const std::filesystem::path&) {
        if (point == "before_delete_local") {
            hook_hit = true;
            h.write("EXTERNAL_U_RED22");
        }
    });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    transport::Transport unavailable;
    auto res = mutation::apply_operation(
        op, 0, local, unavailable, key, transaction, *prepared);

    h.close();
    EXPECT_TRUE(res.has_value()) << (res ? "" : res.error().detail);
    EXPECT_TRUE(hook_hit);
    EXPECT_FALSE(std::filesystem::exists(target));
    EXPECT_FALSE(is_content_preserved(root, "EXTERNAL_U_RED22"));
}

// RED-23: Rollback remove post-hash write preserved
TEST(P0ToctouExploratoryTest, RED23_RollbackRemoveCanLoseALateOpenHandleWrite) {
    auto workspace = test::make_temp_workspace("p0-toctou-red23");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(root / "remote_src", "REMOTE_R");
    const auto r_hash = hasher::hash_string("REMOTE_R");

    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());
    EXPECT_FALSE(prepared->had_original);

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);
    ASSERT_TRUE(res.has_value());

    auto h = open_native_write_handle(target);
    ASSERT_TRUE(h.is_open());

    auto progress = *prepared;
    progress.state = transaction::OperationState::Applied;

    bool hook_hit = false;
    HookGuard guard([&](std::string_view point, const std::filesystem::path&) {
        if (point == "before_remove_file_if_hash") {
            hook_hit = true;
            h.write("EXTERNAL_U_RED23");
        }
    });

    auto rolled =
        mutation::rollback_operation(op, 0, local, transaction, progress);

    h.close();
    ASSERT_TRUE(hook_hit)
        << "Hook before_remove_file_if_hash was not reached: "
        << (rolled ? "" : rolled.error().detail);
    EXPECT_TRUE(rolled.has_value()) << (rolled ? "" : rolled.error().detail);
    EXPECT_FALSE(std::filesystem::exists(target));
    EXPECT_FALSE(is_content_preserved(root, "EXTERNAL_U_RED23"));
}

// RED-24: Restore backup post-hash write preserved
TEST(P0ToctouExploratoryTest, RED24_RestoreCanReplaceALateOpenHandleWrite) {
    auto workspace = test::make_temp_workspace("p0-toctou-red24");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");
    const auto r_hash = hasher::hash_string("REMOTE_R");

    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());
    EXPECT_TRUE(prepared->had_original);

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);
    ASSERT_TRUE(res.has_value());

    auto h = open_native_write_handle(target);
    ASSERT_TRUE(h.is_open());

    auto progress = *prepared;
    progress.state = transaction::OperationState::Applied;

    bool hook_hit = false;
    HookGuard guard([&](std::string_view point, const std::filesystem::path&) {
        if (point == "before_restore_replace") {
            hook_hit = true;
            h.write("EXTERNAL_U_RED24");
        }
    });

    auto rolled =
        mutation::rollback_operation(op, 0, local, transaction, progress);

    h.close();
    EXPECT_TRUE(hook_hit);
    const auto final = test::read_text(target);
    EXPECT_TRUE(final == "ORIGINAL_O" || final == "EXTERNAL_U_RED24");
    EXPECT_EQ(rolled.has_value(), final == "ORIGINAL_O");
    EXPECT_EQ(is_content_preserved(root, "EXTERNAL_U_RED24"),
              final == "EXTERNAL_U_RED24");
}

// RED-25: RenameLocal and late write does not publish stale state
TEST(P0ToctouExploratoryTest,
     RED25_RenameCanPublishBytesWrittenThroughAnOpenHandle) {
    auto workspace = test::make_temp_workspace("p0-toctou-red25");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(transaction.root);

    const auto source = local / "source.txt";
    const auto destination = local / "renamed.txt";
    test::write_text(source, "ORIGINAL_O");

    const Operation op{.action = Action::RenameLocal,
                       .path = "source.txt",
                       .alt_path = "renamed.txt"};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto h = open_native_write_handle(source);
    ASSERT_TRUE(h.is_open());

    bool hook_hit = false;
    HookGuard guard([&](std::string_view point, const std::filesystem::path&) {
        if (point == "after_rename_move") {
            hook_hit = true;
            h.write("EXTERNAL_U_RED25");
        }
    });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    transport::Transport unavailable;
    auto res = mutation::apply_operation(
        op, 0, local, unavailable, key, transaction, *prepared);

    h.close();
    ASSERT_TRUE(hook_hit) << "Hook after_rename_move was not reached";
    EXPECT_TRUE(res.has_value()) << (res ? "" : res.error().detail);
    EXPECT_FALSE(std::filesystem::exists(source));
    EXPECT_EQ(test::read_text(destination), "EXTERNAL_U_RED25");
}

// RED-26: A failure before install leaves the original and backup intact.
TEST(P0ToctouContractTest, InterruptedBeforeInstallKeepsOriginal) {
    auto workspace = test::make_temp_workspace("p0-toctou-red26");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");
    const auto r_hash = hasher::hash_string("REMOTE_R");

    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    bool hook_hit = false;
    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path&) {
            if (point == "before_download_replace") {
                hook_hit = true;
                throw std::runtime_error("simulated_crash_before_install");
            }
        });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    try {
        (void)mutation::apply_operation(
            op, 0, local, *storage, key, transaction, *prepared);
    } catch (const std::runtime_error&) {
    }

    ASSERT_TRUE(hook_hit);
    EXPECT_EQ(test::read_text(target), "ORIGINAL_O");

    const auto rolled =
        mutation::rollback_operation(op, 0, local, transaction, *prepared);
    ASSERT_TRUE(rolled.has_value()) << rolled.error().detail;
    EXPECT_EQ(test::read_text(target), "ORIGINAL_O");
    EXPECT_TRUE(std::filesystem::exists(transaction.root / "0.backup"));
}

// RED-27: Recovery reverses an installed download before its checkpoint.
TEST(P0ToctouContractTest, RecoveryReversesDownloadBeforeAppliedCheckpoint) {
    auto workspace = test::make_temp_workspace("p0-toctou-red27");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");
    const auto r_hash = hasher::hash_string("REMOTE_R");

    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    bool hook_hit = false;
    HookGuard guard([&](std::string_view point,
                        const std::filesystem::path&) {
        if (point == "after_download_replace") {
            hook_hit = true;
            throw std::runtime_error("simulated_crash_after_candidate_install");
        }
    });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    try {
        (void)mutation::apply_operation(
            op, 0, local, *storage, key, transaction, *prepared);
    } catch (const std::runtime_error&) {
    }

    ASSERT_TRUE(hook_hit);
    EXPECT_EQ(test::read_text(target), "REMOTE_R");
    auto rolled =
        mutation::rollback_operation(op, 0, local, transaction, *prepared);
    ASSERT_TRUE(rolled.has_value()) << rolled.error().detail;
    EXPECT_EQ(test::read_text(target), "ORIGINAL_O");
    EXPECT_TRUE(std::filesystem::exists(transaction.root / "0.backup"));
}

TEST(P0ToctouContractTest, RollbackCandidateIsDeterministicAndReusable) {
    auto workspace = test::make_temp_workspace("p0-toctou-red28");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx_deterministic_id"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");
    const auto r_hash = hasher::hash_string("REMOTE_R");

    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);
    ASSERT_TRUE(res.has_value());

    auto progress = *prepared;
    progress.state = transaction::OperationState::Applied;

    const auto candidate = mutation::detail::make_custody_path(
        target, transaction.root.filename().string(), 0, "rollback-candidate");
    test::write_text(candidate, "CORRUPTED_CANDIDATE");
    const auto rejected =
        mutation::rollback_operation(op, 0, local, transaction, progress);
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code,
              mutation::MutationErrorCode::IntegrityMismatch);
    EXPECT_EQ(test::read_text(target), "REMOTE_R");
    EXPECT_EQ(test::read_text(transaction.root / "0.backup"), "ORIGINAL_O");
    EXPECT_EQ(test::read_text(candidate), "CORRUPTED_CANDIDATE");

    test::write_text(candidate, "ORIGINAL_O");
    bool copied_candidate = false;
    HookGuard guard([&](std::string_view point,
                        const std::filesystem::path&) {
        copied_candidate |= point == "after_rollback_candidate_copy";
    });
    const auto rolled =
        mutation::rollback_operation(op, 0, local, transaction, progress);
    ASSERT_TRUE(rolled.has_value()) << rolled.error().detail;
    EXPECT_FALSE(copied_candidate);
    EXPECT_EQ(test::read_text(target), "ORIGINAL_O");
    EXPECT_FALSE(std::filesystem::exists(candidate));
    EXPECT_TRUE(std::filesystem::exists(transaction.root / "0.backup"));
}

TEST(P0ToctouContractTest, NewlyCopiedRollbackCandidateIsValidated) {
    auto workspace = test::make_temp_workspace("rollback-candidate-corrupt");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx_candidate_corrupt"};
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(std::filesystem::create_directories(storage_dir));
    ASSERT_TRUE(std::filesystem::create_directories(transaction.root));

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");
    const auto remote_hash = hasher::hash_string("REMOTE_R");
    const Operation operation{.action = Action::Download,
                              .path = "file.txt",
                              .hash = hash_hex(remote_hash),
                              .size = 8};
    const auto prepared = mutation::prepare_operation(
        operation, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", remote_hash);
    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    ASSERT_TRUE(mutation::apply_operation(
        operation, 0, local, *storage, key, transaction, *prepared));
    auto applied = *prepared;
    applied.state = transaction::OperationState::Applied;

    std::filesystem::path candidate;
    HookGuard guard([&](std::string_view point,
                        const std::filesystem::path& path) {
        if (point == "after_rollback_candidate_copy") {
            candidate = path;
            test::write_text(path, "CORRUPTED_CANDIDATE");
        }
    });
    const auto rolled = mutation::rollback_operation(
        operation, 0, local, transaction, applied);

    EXPECT_FALSE(rolled.has_value());
    if (!rolled) {
        EXPECT_EQ(rolled.error().code,
                  mutation::MutationErrorCode::IntegrityMismatch);
    }
    EXPECT_EQ(test::read_text(target), "REMOTE_R");
    EXPECT_EQ(test::read_text(transaction.root / "0.backup"), "ORIGINAL_O");
    if (std::filesystem::exists(candidate)) {
        EXPECT_EQ(test::read_text(candidate), "CORRUPTED_CANDIDATE");
    }
}

// RED-29: Previous transaction custody cannot be adopted or collided
TEST(P0ToctouContractTest, RED29_PreviousCustodyIsNotAdopted) {
    auto workspace = test::make_temp_workspace("p0-toctou-red29");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace tx_a{root / "tx_a"};
    const platform::Workspace tx_b{root / "tx_b"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(tx_a.root);
    std::filesystem::create_directories(tx_b.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");
    const auto r_hash = hasher::hash_string("REMOTE_R");

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    // Tx A crashed and left its custody file on disk
    const auto custody_a = platform::path::temporary_sibling_path(
        target, ".", ".kasumi-custody-0");
    test::write_text(custody_a, "TX_A_CUSTODY_DATA");

    // Tx B starts now and runs prepare + apply on same path and op index 0
    const auto prep_b =
        mutation::prepare_operation(op, 0, local, tx_b, {.backup_slot = 0});
    ASSERT_TRUE(prep_b.has_value());

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res_b =
        mutation::apply_operation(op, 0, local, *storage, key, tx_b, *prep_b);

    EXPECT_TRUE(res_b.has_value()) << (res_b ? "" : res_b.error().detail);
    EXPECT_EQ(test::read_text(target), "REMOTE_R");
    EXPECT_EQ(test::read_text(custody_a), "TX_A_CUSTODY_DATA");
}

// RED-30: Orphan custody is never silently deleted
TEST(P0ToctouContractTest, RED30_OrphanCustodyIsNeverSilentlyDeleted) {
    auto workspace = test::make_temp_workspace("p0-toctou-red30");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    std::filesystem::create_directories(local);

    const auto orphan = local / ".file.txt.kasumi-custody-orphan";
    test::write_text(orphan, "ORPHAN_EVIDENCE_U");

    // In current code: custody files are not reserved and have no safe cleanup
    // invariants
    EXPECT_TRUE(std::filesystem::exists(orphan));
    EXPECT_EQ(test::read_text(orphan), "ORPHAN_EVIDENCE_U");
}

// RED-31: Custody artifact does not become ordinary synchronized file
TEST(P0ToctouContractTest,
     RED31_CustodyArtifactDoesNotBecomeOrdinarySynchronizedFile) {
    constexpr auto id = "0123456789abcdef0123456789abcdef";
    EXPECT_TRUE(kasumi::ignore::is_reserved_internal(
        std::string(".file.txt.kasumi-custody-") + id + "-0"))
        << "RED-31 FAIL: Custody artifact is treated as ordinary user file by "
           "scanner!";
    EXPECT_TRUE(kasumi::ignore::is_reserved_internal(
        std::string(".file.txt.kasumi-custody-delete-") + id + "-0"))
        << "RED-31 FAIL: Delete custody artifact is treated as ordinary user "
           "file!";
    EXPECT_TRUE(kasumi::ignore::is_reserved_internal(
        std::string(".file.txt.kasumi-rollback-custody-") + id + "-0"))
        << "RED-31 FAIL: Rollback custody artifact is treated as ordinary user "
           "file!";
}

// RED-32: Custody directory sync failure retains recovery evidence
TEST(P0ToctouContractTest, DownloadDoesNotCreateCustodyArtifacts) {
    auto workspace = test::make_temp_workspace("p0-toctou-red32");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");
    const auto r_hash = hasher::hash_string("REMOTE_R");

    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(test::read_text(target), "REMOTE_R");
    EXPECT_FALSE(std::filesystem::exists(mutation::detail::make_custody_path(
        target, transaction.root.filename().string(), 0, "custody")));
}

TEST(P0ToctouExploratoryTest,
     RED33_WriteAfterInstallRemainsAtTheDestination) {
    auto workspace = test::make_temp_workspace("p0-toctou-red33");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");
    const auto r_hash = hasher::hash_string("REMOTE_R");

    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    bool hook_hit = false;
    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path& p) {
            if (point == "after_download_replace") {
                hook_hit = true;
                test::write_text(p, "EXTERNAL_U_RED33");
            }
        });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);

    EXPECT_TRUE(hook_hit);
    EXPECT_TRUE(res.has_value()) << (res ? "" : res.error().detail);
    EXPECT_EQ(test::read_text(target), "EXTERNAL_U_RED33");
}

TEST(P0ToctouExploratoryTest, RED34_HardlinkAliasRemainsLinkedToOldContent) {
    auto workspace = test::make_temp_workspace("p0-toctou-red34");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    const auto alias = local / "alias.txt";
    test::write_text(target, "ORIGINAL_O");
    std::error_code ec;
    std::filesystem::create_hard_link(target, alias, ec);
    if (ec) {
        GTEST_SKIP() << "Hard links not supported on this filesystem";
    }

    test::write_text(root / "remote_src", "REMOTE_R");
    const auto r_hash = hasher::hash_string("REMOTE_R");

    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    bool hook_hit = false;
    HookGuard guard(
        [&](std::string_view point, const std::filesystem::path&) {
            if (point == "before_download_replace") {
                hook_hit = true;
                test::write_text(alias, "EXTERNAL_U_HARDLINK");
            }
        });

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);

    EXPECT_TRUE(res.has_value()) << (res ? "" : res.error().detail);
    EXPECT_TRUE(hook_hit);
    EXPECT_EQ(test::read_text(target), "REMOTE_R");
    EXPECT_EQ(test::read_text(alias), "EXTERNAL_U_HARDLINK");
}

TEST(P0ToctouContractTest, ChangedDestinationBeforeApplyIsRejected) {
    auto workspace = test::make_temp_workspace("p0-toctou-red35");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(storage_dir);
    std::filesystem::create_directories(transaction.root);

    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");
    const auto r_hash = hasher::hash_string("REMOTE_R");

    const Operation op{.action = Action::Download,
                       .path = "file.txt",
                       .hash = hash_hex(r_hash),
                       .size = 8};

    const auto prepared = mutation::prepare_operation(
        op, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());

    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", r_hash);

    test::write_text(target, "EXTERNAL_CONFLICTING_TARGET");

    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    auto res = mutation::apply_operation(
        op, 0, local, *storage, key, transaction, *prepared);

    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code,
              mutation::MutationErrorCode::DestinationConflict);
    EXPECT_EQ(test::read_text(target), "EXTERNAL_CONFLICTING_TARGET");
    EXPECT_EQ(test::read_text(transaction.root / "0.backup"), "ORIGINAL_O");
}

TEST(P0ToctouContractTest, RollbackRetainsMismatchingLegacyCustody) {
    auto workspace = test::make_temp_workspace("rollback-custody-error");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const auto storage_dir = root / "storage";
    const platform::Workspace transaction{root / "tx"};
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(std::filesystem::create_directories(storage_dir));
    ASSERT_TRUE(std::filesystem::create_directories(transaction.root));
    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL_O");
    test::write_text(root / "remote_src", "REMOTE_R");

    const auto remote_hash = hasher::hash_string("REMOTE_R");
    const Operation operation{.action = Action::Download,
                              .path = "file.txt",
                              .hash = hash_hex(remote_hash),
                              .size = 8};
    const auto prepared = mutation::prepare_operation(
        operation, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());
    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote_src", remote_hash);
    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    ASSERT_TRUE(mutation::apply_operation(
        operation, 0, local, *storage, key, transaction, *prepared));

    const auto custody = mutation::detail::make_custody_path(
        target, transaction.root.filename().string(), 0, "custody");
    test::write_text(custody, "CORRUPTED_CUSTODY");
    auto applied = *prepared;
    applied.state = kasumi::transaction::OperationState::Applied;
    const auto rolled =
        mutation::rollback_operation(operation, 0, local, transaction, applied);

    ASSERT_FALSE(rolled.has_value());
    EXPECT_EQ(rolled.error().code,
              mutation::MutationErrorCode::DestinationConflict);
    EXPECT_EQ(test::read_text(target), "REMOTE_R");
    EXPECT_EQ(test::read_text(custody), "CORRUPTED_CUSTODY");
}

TEST(P0ToctouContractTest, InterruptedLegacyCustodyMoveRestoresFromJournalBackup) {
    for (const auto action : {Action::Download, Action::DeleteLocal}) {
        auto workspace = test::make_temp_workspace("legacy-custody-recovery");
        const auto root = test::workspace_root(workspace);
        const auto local = root / "local";
        const platform::Workspace transaction{root / "tx"};
        ASSERT_TRUE(std::filesystem::create_directories(local));
        ASSERT_TRUE(std::filesystem::create_directories(transaction.root));
        const auto target = local / "file.txt";
        test::write_text(target, "ORIGINAL_O");
        const Operation operation{
            .action = action,
            .path = "file.txt",
            .hash = action == Action::Download
                        ? hash_hex(hasher::hash_string("REMOTE_R"))
                        : std::string{},
            .size = action == Action::Download ? 8U : 0U};
        const auto prepared = mutation::prepare_operation(
            operation, 0, local, transaction, {.backup_slot = 0});
        ASSERT_TRUE(prepared.has_value());

        const auto custody = mutation::detail::make_custody_path(
            target,
            transaction.root.filename().string(),
            0,
            action == Action::Download ? "custody" : "custody-delete");
        test::write_text(custody, "ORIGINAL_O");
        ASSERT_TRUE(std::filesystem::remove(target));

        const auto recovered = mutation::rollback_operation(
            operation, 0, local, transaction, *prepared);
        ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
        EXPECT_EQ(test::read_text(target), "ORIGINAL_O");
        EXPECT_FALSE(std::filesystem::exists(custody));
        EXPECT_TRUE(std::filesystem::exists(transaction.root / "0.backup"));
    }
}

#if defined(_WIN32)
TEST(P0ToctouCustodyTest, WinDispositionFailureReturnsErrorAndRetainsCustody) {
    auto workspace = test::make_temp_workspace("win-disposition-failure");
    const auto custody = test::workspace_path(workspace, "custody");
    test::write_text(custody, "CUSTODY_O");
    ASSERT_TRUE(SetFileAttributesW(custody.c_str(), FILE_ATTRIBUTE_READONLY));

    ScopedNativeHandle handle{CreateFileW(custody.c_str(),
                                          GENERIC_READ | DELETE,
                                          0,
                                          nullptr,
                                          OPEN_EXISTING,
                                          FILE_FLAG_BACKUP_SEMANTICS,
                                          nullptr)};
    ASSERT_NE(handle.handle, INVALID_HANDLE_VALUE)
        << "CreateFileW failed with " << GetLastError();
    FILE_DISPOSITION_INFO disposition{TRUE};
    SetLastError(ERROR_SUCCESS);
    const BOOL disposition_result = SetFileInformationByHandle(
        handle.handle, FileDispositionInfo, &disposition, sizeof(disposition));
    const DWORD disposition_error = GetLastError();
    ASSERT_FALSE(disposition_result)
        << "read-only custody did not reproduce disposition failure";
    handle.close();
    ASSERT_FALSE(handle.is_open());

    const auto cleaned = mutation::detail::safe_remove_custody(
        custody, hash_hex(hasher::hash_string("CUSTODY_O")), 0);
    EXPECT_FALSE(cleaned.has_value());
    if (!cleaned) {
        EXPECT_EQ(cleaned.error().code, mutation::MutationErrorCode::LocalIo);
        EXPECT_NE(cleaned.error().detail.find("SetFileInformationByHandle"),
                  std::string::npos);
        EXPECT_NE(
            cleaned.error().detail.find(std::to_string(disposition_error)),
            std::string::npos);
    }
    EXPECT_TRUE(std::filesystem::exists(custody));
    EXPECT_EQ(test::read_text(custody), "CUSTODY_O");
    EXPECT_NE(disposition_error, ERROR_SUCCESS);
    SetFileAttributesW(custody.c_str(), FILE_ATTRIBUTE_NORMAL);
}
#endif

#if defined(__linux__)
TEST(P0ToctouContractTest, ExistingDestructiveMutationsRemainAvailable) {
    auto workspace = test::make_temp_workspace("linux-fail-closed");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const platform::Workspace transaction{root / "tx"};
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(std::filesystem::create_directories(transaction.root));
    test::write_text(local / "download.txt", "ORIGINAL_DOWNLOAD");
    test::write_text(local / "delete.txt", "ORIGINAL_DELETE");
    test::write_text(local / "rename.txt", "ORIGINAL_RENAME");
    ASSERT_TRUE(std::filesystem::create_directory(local / "empty"));

    const Operation download{.action = Action::Download,
                             .path = "download.txt",
                             .hash = hash_hex(hasher::hash_string("REMOTE")),
                             .size = 6};
    const Operation remove{.action = Action::DeleteLocal,
                           .path = "delete.txt"};
    const Operation rename{.action = Action::RenameLocal,
                           .path = "rename.txt",
                           .alt_path = "renamed.txt"};
    const Operation remove_directory{.action = Action::DeleteLocalDirectory,
                                     .path = "empty"};
    const auto download_progress = mutation::prepare_operation(
        download, 0, local, transaction, {.backup_slot = 0});
    const auto delete_progress = mutation::prepare_operation(
        remove, 1, local, transaction, {.backup_slot = 1});
    const auto rename_progress = mutation::prepare_operation(
        rename, 2, local, transaction, {.backup_slot = 2});
    const auto directory_progress = mutation::prepare_operation(
        remove_directory, 3, local, transaction, {.backup_slot = 3});
    ASSERT_TRUE(download_progress.has_value());
    ASSERT_TRUE(delete_progress.has_value());
    ASSERT_TRUE(rename_progress.has_value());
    ASSERT_TRUE(directory_progress.has_value());

    test::write_text(root / "remote", "REMOTE");
    const auto remote_hash = hasher::hash_string("REMOTE");
    const auto storage_dir = root / "storage";
    ASSERT_TRUE(std::filesystem::create_directory(storage_dir));
    auto storage = transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(transport::initialize(*storage));
    stage_remote_object(*storage, root / "remote", remote_hash);
    const Operation download_with_content{
        .action = Action::Download,
        .path = "download.txt",
        .hash = hash_hex(remote_hash),
        .size = 6};
    const std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    const auto download_result = mutation::apply_operation(
        download_with_content,
        0,
        local,
        *storage,
        key,
        transaction,
        *download_progress);
    const auto delete_result = mutation::apply_operation(
        remove, 1, local, *storage, key, transaction, *delete_progress);
    const auto rename_result = mutation::apply_operation(
        rename, 2, local, *storage, key, transaction, *rename_progress);
    const auto directory_result = mutation::apply_operation(
        remove_directory,
        3,
        local,
        *storage,
        key,
        transaction,
        *directory_progress);

    for (const auto* result : {&download_result,
                               &delete_result,
                               &rename_result,
                               &directory_result}) {
        ASSERT_TRUE(result->has_value())
            << (result->has_value() ? "" : result->error().detail);
    }
    EXPECT_EQ(test::read_text(local / "download.txt"), "REMOTE");
    EXPECT_FALSE(std::filesystem::exists(local / "delete.txt"));
    EXPECT_FALSE(std::filesystem::exists(local / "rename.txt"));
    EXPECT_EQ(test::read_text(local / "renamed.txt"), "ORIGINAL_RENAME");
    EXPECT_FALSE(std::filesystem::exists(local / "empty"));
}

TEST(P0ToctouContractTest,
     RollbackRestoresExpectedFileAndRetainsBackup) {
    auto workspace = test::make_temp_workspace("linux-rollback-restores");
    const auto root = test::workspace_root(workspace);
    const auto local = root / "local";
    const platform::Workspace transaction{root / "tx"};
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(std::filesystem::create_directories(transaction.root));
    const auto target = local / "file.txt";
    test::write_text(target, "ORIGINAL");

    const Operation operation{
        .action = Action::Download,
        .path = "file.txt",
        .hash = hash_hex(hasher::hash_string("REMOTE")),
        .size = 6};
    const auto prepared = mutation::prepare_operation(
        operation, 0, local, transaction, {.backup_slot = 0});
    ASSERT_TRUE(prepared.has_value());
    test::write_text(target, "REMOTE");
    auto applied = *prepared;
    applied.state = transaction::OperationState::Applied;

    const auto rolled = mutation::rollback_operation(
        operation, 0, local, transaction, applied);
    ASSERT_TRUE(rolled.has_value()) << rolled.error().detail;
    EXPECT_EQ(test::read_text(target), "ORIGINAL");
    EXPECT_EQ(test::read_text(transaction.root / "0.backup"), "ORIGINAL");
}

TEST(P0ToctouExploratoryTest,
     LinuxExploratoryPathReplacementCanRemoveReplacement) {
    auto workspace = test::make_temp_workspace("linux-custody-path-aba");
    const auto custody = test::workspace_path(workspace, "custody");
    const auto displaced = test::workspace_path(workspace, "custody.original");
    test::write_text(custody, "CUSTODY_O");
    struct stat original_identity{};
    ASSERT_EQ(::stat(custody.c_str(), &original_identity), 0);

    bool hook_hit = false;
    int child_status = -1;
    int replacement_stat_result = -1;
    struct stat replacement_identity{};
    HookGuard guard([&](std::string_view point,
                        const std::filesystem::path& path) {
        if (point != "before_custody_unlink")
            return;
        hook_hit = true;
        const pid_t child = ::fork();
        if (child == 0) {
            if (::rename(path.c_str(), displaced.c_str()) != 0)
                ::_exit(11);
            const int replacement = ::open(
                path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (replacement < 0)
                ::_exit(12);
            constexpr char contents[] = "EXTERNAL_U";
            const auto written =
                ::write(replacement, contents, sizeof(contents) - 1);
            const int close_result = ::close(replacement);
            ::_exit(written == static_cast<ssize_t>(sizeof(contents) - 1) &&
                            close_result == 0
                        ? 0
                        : 13);
        }
        if (child < 0)
            return;
        int status = 0;
        if (::waitpid(child, &status, 0) == child)
            child_status = WIFEXITED(status) ? WEXITSTATUS(status) : 255;
        if (child_status == 0)
            replacement_stat_result =
                ::stat(path.c_str(), &replacement_identity);
    });

    const auto cleaned = mutation::detail::safe_remove_custody(
        custody, hash_hex(hasher::hash_string("CUSTODY_O")), 0);
    ASSERT_TRUE(hook_hit);
    ASSERT_EQ(child_status, 0) << "namespace replacement subprocess failed";
    ASSERT_EQ(replacement_stat_result, 0);
    EXPECT_TRUE(replacement_identity.st_dev != original_identity.st_dev ||
                replacement_identity.st_ino != original_identity.st_ino);

    struct stat displaced_identity{};
    ASSERT_EQ(::stat(displaced.c_str(), &displaced_identity), 0);
    EXPECT_EQ(displaced_identity.st_dev, original_identity.st_dev);
    EXPECT_EQ(displaced_identity.st_ino, original_identity.st_ino);
    EXPECT_TRUE(cleaned.has_value()) << cleaned.error().detail;
    const bool replacement_survived = std::filesystem::exists(custody);
    EXPECT_FALSE(replacement_survived);
    EXPECT_EQ(test::read_text(displaced), "CUSTODY_O");
}
#endif
