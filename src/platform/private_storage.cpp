#include "platform/private_storage.hpp"

#include "detail.hpp"
#include "platform/durability.hpp"
#include "platform/path.hpp"
#include "platform/random.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <format>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

// clang-format off
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
// clang-format on

namespace kasumi::platform::private_storage {
namespace {

std::string system_error(std::string_view operation,
                         const std::error_code& error) {
    return std::string{operation} + ": " + error.message();
}

std::unexpected<StreamError> make_stream_error(StreamErrorKind kind,
                                               std::string detail,
                                               std::error_code error = {}) {
    return std::unexpected(StreamError{
        .kind = kind, .detail = std::move(detail), .system_error = error});
}

#if defined(_WIN32)

std::string windows_error(std::string_view operation, DWORD code) {
    return system_error(
        operation,
        std::error_code{static_cast<int>(code), std::system_category()});
}

FileIdentity to_file_identity(const FILE_ID_INFO& info) noexcept {
    FileIdentity identity{.volume_or_dev = info.VolumeSerialNumber,
                          .valid = true};
    std::memcpy(
        &identity.file_id_low, info.FileId.Identifier, sizeof(std::uint64_t));
    std::memcpy(&identity.file_id_high,
                info.FileId.Identifier + sizeof(std::uint64_t),
                sizeof(std::uint64_t));
    return identity;
}

using UniqueLocalMem = std::unique_ptr<void, decltype(&LocalFree)>;

struct ProcessSecurityContext {
    std::array<std::byte, SECURITY_MAX_SID_SIZE> user_sid{};
    std::array<std::byte, SECURITY_MAX_SID_SIZE> system_sid{};
    std::array<std::byte, SECURITY_MAX_SID_SIZE> admins_sid{};
    bool has_admins_sid = false;
    bool valid = false;
};

ProcessSecurityContext build_process_security_context() noexcept {
    ProcessSecurityContext context{};
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return context;
    }
    PrivateHandle token_guard{reinterpret_cast<std::intptr_t>(token)};
    std::array<std::byte, sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE> buffer{};
    DWORD returned_size = 0;
    if (!GetTokenInformation(token,
                             TokenUser,
                             buffer.data(),
                             static_cast<DWORD>(buffer.size()),
                             &returned_size)) {
        return context;
    }
    const auto* token_user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    if (!token_user->User.Sid || !IsValidSid(token_user->User.Sid)) {
        return context;
    }
    const DWORD sid_length = GetLengthSid(token_user->User.Sid);
    if (sid_length == 0 || sid_length > context.user_sid.size()) {
        return context;
    }
    std::memcpy(context.user_sid.data(), token_user->User.Sid, sid_length);

    DWORD system_sid_size = static_cast<DWORD>(context.system_sid.size());
    if (!CreateWellKnownSid(WinLocalSystemSid,
                            nullptr,
                            context.system_sid.data(),
                            &system_sid_size) ||
        !IsValidSid(context.system_sid.data())) {
        return context;
    }
    DWORD admins_sid_size = static_cast<DWORD>(context.admins_sid.size());
    context.has_admins_sid =
        CreateWellKnownSid(WinBuiltinAdministratorsSid,
                           nullptr,
                           context.admins_sid.data(),
                           &admins_sid_size) != 0 &&
        IsValidSid(context.admins_sid.data());
    context.valid = true;
    return context;
}

const ProcessSecurityContext& get_process_security_context() noexcept {
    static const ProcessSecurityContext cached = build_process_security_context();
    return cached;
}

std::expected<UniqueLocalMem, std::string> security_descriptor(bool directory) {
    auto context = get_process_security_context();
    if (!context.valid) {
        return std::unexpected(
            windows_error("OpenProcessToken failed", GetLastError()));
    }
    wchar_t* sid_text = nullptr;
    if (!ConvertSidToStringSidW(context.user_sid.data(), &sid_text)) {
        return std::unexpected(
            windows_error("ConvertSidToStringSidW failed", GetLastError()));
    }
    UniqueLocalMem sid_guard{sid_text, LocalFree};
    const std::wstring inherit = directory ? L"OICI" : L"";
    const std::wstring sddl = L"D:P(A;" + inherit + L";FA;;;SY)(A;" + inherit +
                              L";FA;;;" + sid_text + L")";

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        return std::unexpected(windows_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed",
            GetLastError()));
    }
    return UniqueLocalMem{descriptor, LocalFree};
}

enum class SecurityInspection {
    Compliant,
    NeedsDaclRepair,
    UntrustedOwner,
    QueryFailed,
};

SecurityInspection inspect_path_security(const std::filesystem::path& path,
                                         bool directory) noexcept {
    const auto& context = get_process_security_context();
    if (!context.valid) {
        return SecurityInspection::QueryFailed;
    }

    PSID owner_sid = nullptr;
    PACL current_dacl = nullptr;
    PSECURITY_DESCRIPTOR raw_sd = nullptr;
    if (GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()),
                              SE_FILE_OBJECT,
                              OWNER_SECURITY_INFORMATION |
                                  DACL_SECURITY_INFORMATION,
                              &owner_sid,
                              nullptr,
                              &current_dacl,
                              nullptr,
                              &raw_sd) != ERROR_SUCCESS ||
        !raw_sd) {
        if (raw_sd) {
            LocalFree(raw_sd);
        }
        return SecurityInspection::QueryFailed;
    }
    UniqueLocalMem sd_guard{raw_sd, LocalFree};

    if (!owner_sid || !IsValidSid(owner_sid)) {
        return SecurityInspection::UntrustedOwner;
    }
    const bool trusted_owner =
        EqualSid(owner_sid,
                 const_cast<std::byte*>(context.user_sid.data())) ||
        EqualSid(owner_sid,
                 const_cast<std::byte*>(context.system_sid.data())) ||
        (context.has_admins_sid &&
         EqualSid(owner_sid,
                  const_cast<std::byte*>(context.admins_sid.data())));
    if (!trusted_owner) {
        return SecurityInspection::UntrustedOwner;
    }
    if (!current_dacl) {
        return SecurityInspection::NeedsDaclRepair;
    }

    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    ACL_SIZE_INFORMATION info{};
    if (!GetSecurityDescriptorControl(raw_sd, &control, &revision) ||
        (control & SE_DACL_PROTECTED) == 0 ||
        !GetAclInformation(
            current_dacl, &info, sizeof(info), AclSizeInformation) ||
        info.AceCount != 2) {
        return SecurityInspection::NeedsDaclRepair;
    }

    const DWORD expected_flags =
        directory ? (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) : 0;
    bool user_seen = false;
    bool system_seen = false;

    for (DWORD i = 0; i < info.AceCount; ++i) {
        void* ace_ptr = nullptr;
        if (!GetAce(current_dacl, i, &ace_ptr) || !ace_ptr) {
            return SecurityInspection::NeedsDaclRepair;
        }
        const auto* header = static_cast<const ACE_HEADER*>(ace_ptr);
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(ace_ptr);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
            (header->AceFlags & INHERITED_ACE) != 0 ||
            header->AceFlags != expected_flags ||
            (ace->Mask & FILE_ALL_ACCESS) != FILE_ALL_ACCESS) {
            return SecurityInspection::NeedsDaclRepair;
        }
        auto* sid = const_cast<DWORD*>(&ace->SidStart);
        if (EqualSid(sid, const_cast<std::byte*>(context.user_sid.data()))) {
            user_seen = true;
        } else if (EqualSid(
                       sid,
                       const_cast<std::byte*>(context.system_sid.data()))) {
            system_seen = true;
        } else {
            return SecurityInspection::NeedsDaclRepair;
        }
    }
    return (user_seen && system_seen) ? SecurityInspection::Compliant
                                      : SecurityInspection::NeedsDaclRepair;
}

std::expected<void, std::string> apply_acl(const std::filesystem::path& path,
                                           bool directory) {
    const auto inspection = inspect_path_security(path, directory);
    if (inspection == SecurityInspection::Compliant) {
        return {};
    }
    if (inspection == SecurityInspection::UntrustedOwner) {
        return std::unexpected("unexpected owner on private path '" +
                               platform::path::to_utf8(path) + "'");
    }

    auto descriptor = security_descriptor(directory);
    if (!descriptor) {
        return std::unexpected(descriptor.error());
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    if (!GetSecurityDescriptorDacl(
            descriptor->get(), &present, &dacl, &defaulted) ||
        !present) {
        return std::unexpected(
            windows_error("GetSecurityDescriptorDacl failed", GetLastError()));
    }
    auto writable = path.wstring();
    const auto result = SetNamedSecurityInfoW(
        writable.data(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        dacl,
        nullptr);
    if (result != ERROR_SUCCESS) {
        return std::unexpected(
            windows_error("SetNamedSecurityInfoW failed", result));
    }
    return {};
}

std::expected<DWORD, std::string>
checked_attributes(const std::filesystem::path& path) {
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return std::unexpected(
            windows_error("GetFileAttributesW failed", GetLastError()));
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return std::unexpected("reparse point is not allowed in '" +
                               platform::path::to_utf8(path) + "'");
    }
    return attributes;
}

#else

CleanupResult map_unlink_errno(int err) noexcept {
    if (err == ENOENT) {
        return CleanupResult::AlreadyAbsent;
    }
    if (err == EACCES || err == EPERM || err == EROFS) {
        return CleanupResult::AccessDenied;
    }
    return CleanupResult::FilesystemError;
}

std::string cleanup_created_file_on_error(const std::filesystem::path& path,
                                          int verify_fd) noexcept {
    struct stat st_path{};
    if (::lstat(path.c_str(), &st_path) != 0 || !S_ISREG(st_path.st_mode)) {
        return {};
    }
    if (verify_fd >= 0) {
        struct stat st_f{};
        if (::fstat(verify_fd, &st_f) != 0 || st_f.st_dev != st_path.st_dev ||
            st_f.st_ino != st_path.st_ino) {
            return {};
        }
    }
    if (::unlink(path.c_str()) != 0) {
        return " (cleanup unlink failed: " +
               std::error_code{errno, std::generic_category()}.message() + ")";
    }
    return {};
}

FileIdentity to_file_identity(const struct stat& status) noexcept {
    return FileIdentity{
        .volume_or_dev = static_cast<std::uint64_t>(status.st_dev),
        .file_id_low = static_cast<std::uint64_t>(status.st_ino),
        .valid = true};
}

std::expected<struct stat, std::string>
checked_status(const std::filesystem::path& path) {
    struct stat status{};
    if (::lstat(path.c_str(), &status) != 0) {
        return std::unexpected(system_error(
            "lstat failed", std::error_code{errno, std::generic_category()}));
    }
    if (S_ISLNK(status.st_mode)) {
        return std::unexpected("symlink is not allowed in '" +
                               platform::path::to_utf8(path) + "'");
    }
    return status;
}

#endif

std::expected<void, std::string>
protect_entry(const std::filesystem::path& path,
              bool directory,
              const char* empty_msg,
              const char* mismatch_msg) {
    if (path.empty()) {
        return std::unexpected(empty_msg);
    }
#if defined(_WIN32)
    auto attributes = checked_attributes(path);
    if (!attributes) {
        return std::unexpected(attributes.error());
    }
    const bool is_dir = (*attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (is_dir != directory) {
        return std::unexpected(std::format("{}'{}'", mismatch_msg,
                                           platform::path::to_utf8(path)));
    }
    return apply_acl(path, directory);
#else
    auto status = checked_status(path);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (directory ? !S_ISDIR(status->st_mode) : !S_ISREG(status->st_mode)) {
        return std::unexpected(std::format("{}'{}'", mismatch_msg,
                                           platform::path::to_utf8(path)));
    }
    const uid_t expected_uid = ::geteuid();
    if (status->st_uid != expected_uid) {
        return std::unexpected("unexpected owner on private path '" +
                               platform::path::to_utf8(path) + "'");
    }
    const mode_t mode = directory ? 0700 : 0600;
    if ((status->st_mode & 0777) == mode) {
        return {};
    }
    int flags = O_RDONLY | O_NOFOLLOW;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    if (directory) {
#ifdef O_DIRECTORY
        flags |= O_DIRECTORY;
#endif
    }
    const int fd = ::open(path.c_str(), flags);
    if (fd >= 0) {
        PrivateHandle fd_guard{fd};
        struct stat opened_status{};
        if (::fstat(fd, &opened_status) != 0) {
            return std::unexpected(
                system_error("fstat failed",
                             std::error_code{errno, std::generic_category()}));
        }
        if ((directory ? !S_ISDIR(opened_status.st_mode)
                       : !S_ISREG(opened_status.st_mode)) ||
            opened_status.st_dev != status->st_dev ||
            opened_status.st_ino != status->st_ino ||
            opened_status.st_uid != expected_uid) {
            return std::unexpected("private path identity changed during protection '" +
                                   platform::path::to_utf8(path) + "'");
        }
        if (::fchmod(fd, mode) != 0) {
            return std::unexpected(system_error(
                directory ? "fchmod 0700 failed" : "fchmod 0600 failed",
                std::error_code{errno, std::generic_category()}));
        }
        return {};
    }
    const int open_err = errno;
    if (directory && open_err == EACCES) {
        if (::chmod(path.c_str(), mode) != 0) {
            return std::unexpected(system_error(
                "chmod 0700 failed",
                std::error_code{errno, std::generic_category()}));
        }
        return {};
    }
    return std::unexpected(system_error(
        "open failed during private storage protection",
        std::error_code{open_err, std::generic_category()}));
#endif
}

#if defined(_WIN32)
std::expected<void, std::string>
protect_windows_tree(const std::filesystem::path& root) {
    auto protected_root = protect_directory(root);
    if (!protected_root) {
        return protected_root;
    }
    return platform::detail::walk_windows_tree(
        root,
        false,
        [](void*,
           const std::filesystem::path& path,
           std::uint32_t attrs) -> std::expected<void, std::string> {
            if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                return protect_directory(path);
            }
            if ((attrs & FILE_ATTRIBUTE_DEVICE) == 0) {
                return protect_file(path);
            }
            return std::unexpected("invalid internal object in '" +
                                   platform::path::to_utf8(path) + "'");
        },
        nullptr);
}
#endif

} // namespace

#if defined(_WIN32)
} // namespace kasumi::platform::private_storage

namespace kasumi::platform::detail {

std::expected<void, std::string>
walk_windows_tree(const std::filesystem::path& root,
                  bool postorder_dirs,
                  WalkEntryFn on_entry,
                  void* context) {
    struct Frame {
        std::filesystem::path path;
        bool postorder{false};
    };
    const auto win_err = [](std::string_view op,
                            const std::filesystem::path& p,
                            DWORD code) {
        return std::string{op} + " for '" + platform::path::to_utf8(p) + "': " +
               std::error_code{static_cast<int>(code), std::system_category()}
                   .message();
    };
    std::vector<Frame> stack{{root, false}};
    while (!stack.empty()) {
        auto frame = std::move(stack.back());
        stack.pop_back();
        if (frame.postorder) {
            if (auto res =
                    on_entry(context, frame.path, FILE_ATTRIBUTE_DIRECTORY);
                !res) {
                return res;
            }
            continue;
        }
        auto pattern = frame.path.native();
        pattern.append(L"\\*");
        WIN32_FIND_DATAW entry{};
        const auto search = FindFirstFileW(pattern.c_str(), &entry);
        if (search == INVALID_HANDLE_VALUE) {
            const auto code = GetLastError();
            if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
                if (postorder_dirs) {
                    stack.push_back({std::move(frame.path), true});
                }
                continue;
            }
            return std::unexpected(
                win_err("FindFirstFileW failed", frame.path, code));
        }
        if (postorder_dirs) {
            stack.push_back({frame.path, true});
        }
        std::string failure;
        do {
            const std::wstring_view name{entry.cFileName};
            if (name == L"." || name == L"..") {
                continue;
            }
            auto native_path = frame.path.native();
            native_path.push_back(L'\\');
            native_path.append(entry.cFileName);
            const std::filesystem::path child{std::move(native_path)};
            if ((entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                failure = "reparse point is not allowed in '" +
                          platform::path::to_utf8(child) + "'";
                break;
            }
            if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                if (!postorder_dirs) {
                    if (auto res =
                            on_entry(context, child, entry.dwFileAttributes);
                        !res) {
                        failure = res.error();
                        break;
                    }
                }
                stack.push_back({child, false});
            } else {
                if (auto res = on_entry(context, child, entry.dwFileAttributes);
                    !res) {
                    failure = res.error();
                    break;
                }
            }
        } while (FindNextFileW(search, &entry));
        const auto enumeration_error = GetLastError();
        FindClose(search);
        if (!failure.empty()) {
            return std::unexpected(std::move(failure));
        }
        if (enumeration_error != ERROR_NO_MORE_FILES &&
            enumeration_error != ERROR_FILE_NOT_FOUND &&
            enumeration_error != ERROR_PATH_NOT_FOUND) {
            return std::unexpected(
                win_err("FindNextFileW failed", frame.path, enumeration_error));
        }
    }
    return {};
}

} // namespace kasumi::platform::detail

namespace kasumi::platform::private_storage {
#endif

std::expected<void, std::string>
create_directory(const std::filesystem::path& path) {
    if (path.empty()) {
        return std::unexpected("empty private directory path");
    }
#if defined(_WIN32)
    auto descriptor = security_descriptor(true);
    if (!descriptor) {
        return std::unexpected(descriptor.error());
    }
    SECURITY_ATTRIBUTES attributes{
        .nLength = sizeof(SECURITY_ATTRIBUTES),
        .lpSecurityDescriptor = descriptor->get(),
        .bInheritHandle = FALSE,
    };
    if (!CreateDirectoryW(path.c_str(), &attributes)) {
        return std::unexpected(
            windows_error("CreateDirectoryW failed", GetLastError()));
    }
#else
    if (::mkdir(path.c_str(), 0700) != 0) {
        return std::unexpected(system_error(
            "mkdir failed", std::error_code{errno, std::generic_category()}));
    }
#endif
    return {};
}

std::expected<void, std::string>
protect_directory(const std::filesystem::path& path) {
    return protect_entry(
        path, true, "empty private directory path", "directory expected at ");
}

std::expected<void, std::string>
ensure_directory(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory ||
        (!error && status.type() == std::filesystem::file_type::not_found)) {
        return private_storage::create_directory(path);
    }
    if (error) {
        return std::unexpected(system_error("symlink_status failed", error));
    }
    return protect_directory(path);
}

std::expected<void, std::string>
protect_tree(const std::filesystem::path& root) {
#if defined(_WIN32)
    return protect_windows_tree(root);
#else
    auto protected_root = protect_directory(root);
    if (!protected_root) {
        return protected_root;
    }
    std::error_code error;
    std::filesystem::recursive_directory_iterator entries(root, error);
    if (error) {
        return std::unexpected(system_error(
            "could not list '" + platform::path::to_utf8(root) + "'", error));
    }
    const std::filesystem::recursive_directory_iterator end;
    while (entries != end) {
        const auto path = entries->path();
        const auto status = std::filesystem::symlink_status(path, error);
        if (error) {
            if (error == std::errc::no_such_file_or_directory) {
                error.clear();
                entries.increment(error);
                if (error == std::errc::no_such_file_or_directory) {
                    error.clear();
                }
                continue;
            }
            return std::unexpected(system_error(
                "could not inspect '" + platform::path::to_utf8(path) + "'",
                error));
        }
        if (std::filesystem::is_symlink(status)) {
            return std::unexpected("symlink is not allowed in '" +
                                   platform::path::to_utf8(path) + "'");
        }
        std::expected<void, std::string> protected_path;
        if (std::filesystem::is_directory(status)) {
            protected_path = protect_directory(path);
        } else if (std::filesystem::is_regular_file(status)) {
            protected_path = protect_file(path);
        } else {
            return std::unexpected("invalid internal object in '" +
                                   platform::path::to_utf8(path) + "'");
        }
        if (!protected_path) {
            return protected_path;
        }
        entries.increment(error);
        if (error) {
            if (error == std::errc::no_such_file_or_directory) {
                error.clear();
                continue;
            }
            return std::unexpected(system_error(
                "could not advance in '" + platform::path::to_utf8(root) + "'",
                error));
        }
    }
    return {};
#endif
}

std::expected<PrivateOutputFile, CreateFileError>
create_private_file(const std::filesystem::path& path) {
    if (path.empty()) {
        return std::unexpected(
            CreateFileError{"empty private file path", false});
    }
#if defined(_WIN32)
    auto descriptor = security_descriptor(false);
    if (!descriptor) {
        return std::unexpected(CreateFileError{descriptor.error(), false});
    }
    SECURITY_ATTRIBUTES attributes{
        .nLength = sizeof(SECURITY_ATTRIBUTES),
        .lpSecurityDescriptor = descriptor->get(),
        .bInheritHandle = FALSE,
    };
    const auto file = CreateFileW(path.c_str(),
                                  GENERIC_READ | GENERIC_WRITE | DELETE,
                                  FILE_SHARE_READ | FILE_SHARE_DELETE,
                                  &attributes,
                                  CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL,
                                  nullptr);
    const DWORD create_error =
        (file == INVALID_HANDLE_VALUE) ? GetLastError() : ERROR_SUCCESS;
    if (file == INVALID_HANDLE_VALUE) {
        const auto code = create_error;
        const bool is_col =
            (code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS);
        auto detail = "CreateFileW failed for '" +
                      platform::path::to_utf8(path) + "' (Win32 error " +
                      std::to_string(code) + ")";
        if (code == ERROR_PATH_NOT_FOUND && path.native().size() >= MAX_PATH &&
            GetFileAttributesW(path.parent_path().c_str()) !=
                INVALID_FILE_ATTRIBUTES) {
            detail =
                "Windows rejected a " + std::to_string(path.native().size()) +
                "-character path although its parent exists; enable Windows "
                "long-path support or shorten the profile path";
        }
        return std::unexpected(
            CreateFileError{windows_error(detail, code), is_col});
    }
    FILE_ID_INFO id{};
    const BOOL id_ok =
        GetFileInformationByHandleEx(file, FileIdInfo, &id, sizeof(id));
    if (!id_ok) {
        const auto code = GetLastError();
        FILE_DISPOSITION_INFO disp_info{TRUE};
        SetFileInformationByHandle(
            file, FileDispositionInfo, &disp_info, sizeof(disp_info));
        CloseHandle(file);
        return std::unexpected(CreateFileError{
            windows_error("Failed to query file identity", code), false});
    }
    const auto identity = to_file_identity(id);
    return PrivateOutputFile{
        .handle = reinterpret_cast<std::intptr_t>(file),
        .path = path,
        .identity = identity,
    };
#else
    int flags = O_RDWR | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int file = ::open(path.c_str(), flags, 0600);
    if (file < 0) {
        const bool is_col = (errno == EEXIST);
        return std::unexpected(CreateFileError{
            system_error("open failed",
                         std::error_code{errno, std::generic_category()}),
            is_col});
    }
    if (::fchmod(file, 0600) != 0) {
        const auto error = errno;
        const auto cleanup_detail = cleanup_created_file_on_error(path, file);
        ::close(file);
        return std::unexpected(CreateFileError{
            system_error("fchmod 0600 failed" + cleanup_detail,
                         std::error_code{error, std::generic_category()}),
            false});
    }
    struct stat st{};
    FileIdentity identity{};
    if (::fstat(file, &st) != 0) {
        const auto error = errno;
        const auto cleanup_detail = cleanup_created_file_on_error(path, -1);
        ::close(file);
        return std::unexpected(CreateFileError{
            system_error("fstat failed" + cleanup_detail,
                         std::error_code{error, std::generic_category()}),
            false});
    }
    identity.volume_or_dev = static_cast<std::uint64_t>(st.st_dev);
    identity.file_id_low = static_cast<std::uint64_t>(st.st_ino);
    identity.valid = true;
    return PrivateOutputFile{
        .handle = static_cast<std::intptr_t>(file),
        .path = path,
        .identity = identity,
    };
#endif
}

void close_raw_handle(std::intptr_t handle) noexcept {
    if (handle == invalid_private_handle) {
        return;
    }
#if defined(_WIN32)
    CloseHandle(reinterpret_cast<HANDLE>(handle));
#else
    ::close(static_cast<int>(handle));
#endif
}

void close_private_file(PrivateOutputFile& file) noexcept {
    file.handle.close();
}

std::expected<void, std::string>
create_file(const std::filesystem::path& path) {
    auto file = create_private_file(path);
    if (!file) {
        return std::unexpected(file.error().message);
    }
    close_private_file(*file);
    return {};
}

std::expected<void, std::string> write_private_file(PrivateOutputFile& file,
                                                    const void* data,
                                                    std::size_t size) {
    if (!file.is_open()) {
        return std::unexpected("private file is not open for writing");
    }
    if (size == 0) {
        return {};
    }
#if defined(_WIN32)
    const char* ptr = static_cast<const char*>(data);
    std::size_t remaining = size;
    while (remaining > 0) {
        const DWORD chunk =
            static_cast<DWORD>(std::min<std::size_t>(remaining, 0xFFFFFFFFUL));
        DWORD written = 0;
        if (!WriteFile(reinterpret_cast<HANDLE>(file.handle.value),
                       ptr,
                       chunk,
                       &written,
                       nullptr) ||
            written == 0) {
            return std::unexpected(
                windows_error("WriteFile failed", GetLastError()));
        }
        ptr += written;
        remaining -= written;
    }
    return {};
#else
    const char* ptr = static_cast<const char*>(data);
    std::size_t remaining = size;
    while (remaining > 0) {
        const ssize_t written =
            ::write(static_cast<int>(file.handle), ptr, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(
                system_error("write failed",
                             std::error_code{errno, std::generic_category()}));
        }
        if (written == 0) {
            return std::unexpected("write returned 0 bytes");
        }
        ptr += written;
        remaining -= static_cast<std::size_t>(written);
    }
    return {};
#endif
}

std::expected<void, std::string>
flush_and_close_private_file(PrivateOutputFile& file) {
    if (!file.is_open()) {
        return {};
    }
#if defined(_WIN32)
    HANDLE h = reinterpret_cast<HANDLE>(file.handle.value);
    if (!FlushFileBuffers(h)) {
        const auto error = GetLastError();
        close_private_file(file);
        return std::unexpected(windows_error("FlushFileBuffers failed", error));
    }
    const HANDLE handle_to_close = reinterpret_cast<HANDLE>(
        std::exchange(file.handle.value, invalid_private_handle));
    if (!CloseHandle(handle_to_close)) {
        const auto error = GetLastError();
        return std::unexpected(windows_error("CloseHandle failed", error));
    }
    return {};
#else
    int fd = static_cast<int>(file.handle);
    while (::fsync(fd) != 0) {
        if (errno == EINTR) {
            continue;
        }
        const auto error = errno;
        close_private_file(file);
        return std::unexpected(system_error(
            "fsync failed", std::error_code{error, std::generic_category()}));
    }
    const int fd_to_close = static_cast<int>(
        std::exchange(file.handle.value, invalid_private_handle));
    if (::close(fd_to_close) != 0) {
        const auto error = errno;
        return std::unexpected(system_error(
            "close failed", std::error_code{error, std::generic_category()}));
    }
    return {};
#endif
}

#if defined(_WIN32)
namespace {

FileIdentity query_windows_identity(const std::filesystem::path& path,
                                    bool want_directory) noexcept {
    const auto handle =
        CreateFileW(path.c_str(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return {};
    }
    PrivateHandle guard{reinterpret_cast<std::intptr_t>(handle)};
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    FILE_ID_INFO id{};
    if (!GetFileInformationByHandleEx(
            handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return {};
    }
    const bool is_dir =
        (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (is_dir != want_directory ||
        !GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id))) {
        return {};
    }
    return to_file_identity(id);
}

} // namespace
#endif

FileIdentity query_file_identity(const std::filesystem::path& path) noexcept {
    if (path.empty()) {
        return {};
    }
#if defined(_WIN32)
    return query_windows_identity(path, false);
#else
    struct stat st{};
    if (::lstat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        return {};
    }
    return to_file_identity(st);
#endif
}

DirectoryIdentity
query_directory_identity(const std::filesystem::path& path) noexcept {
    if (path.empty()) {
        return {};
    }
#if defined(_WIN32)
    return query_windows_identity(path, true);
#else
    const int descriptor = ::open(path.c_str(),
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW
#ifdef O_CLOEXEC
                                      | O_CLOEXEC
#endif
    );
    if (descriptor < 0) {
        return {};
    }
    PrivateHandle guard{descriptor};
    struct stat status{};
    if (::fstat(descriptor, &status) != 0 || !S_ISDIR(status.st_mode)) {
        return {};
    }
    return to_file_identity(status);
#endif
}

std::expected<void, std::string>
publish_private_file(PrivateOutputFile& file,
                     const std::filesystem::path& target_path) {
    if (!file.is_open()) {
        return std::unexpected("private file is not open");
    }
    if (target_path.empty()) {
        return std::unexpected("target path cannot be empty");
    }
    if (!file.identity.valid) {
        return std::unexpected("private file identity is invalid");
    }
#if defined(_WIN32)
    HANDLE h = reinterpret_cast<HANDLE>(file.handle.value);
    FILE_ID_INFO current_id{};
    if (!GetFileInformationByHandleEx(
            h, FileIdInfo, &current_id, sizeof(current_id))) {
        return std::unexpected(
            windows_error("GetFileInformationByHandleEx failed during publish",
                          GetLastError()));
    }
    if (!(to_file_identity(current_id) == file.identity)) {
        return std::unexpected("file handle identity mismatch during publish");
    }

    if (!FlushFileBuffers(h)) {
        const auto code = GetLastError();
        return std::unexpected(windows_error("FlushFileBuffers failed", code));
    }

    std::wstring target_str = target_path.wstring();
    const DWORD rename_info_size = static_cast<DWORD>(
        sizeof(FILE_RENAME_INFO) + target_str.size() * sizeof(WCHAR));
    std::vector<char> buffer(rename_info_size, 0);
    FILE_RENAME_INFO* rename_info =
        reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
    rename_info->ReplaceIfExists = TRUE;
    rename_info->RootDirectory = nullptr;
    rename_info->FileNameLength =
        static_cast<DWORD>(target_str.size() * sizeof(WCHAR));
    std::memcpy(rename_info->FileName,
                target_str.c_str(),
                target_str.size() * sizeof(WCHAR));

    if (!SetFileInformationByHandle(
            h, FileRenameInfo, rename_info, rename_info_size)) {
        const auto code = GetLastError();
        return std::unexpected(
            windows_error("SetFileInformationByHandle rename failed", code));
    }
    file.published = true;
    file.path.clear();
    file.identity.valid = false;
    close_private_file(file);
    return {};
#else
    int fd = static_cast<int>(file.handle);
    while (::fsync(fd) != 0) {
        if (errno == EINTR) {
            continue;
        }
        return std::unexpected(system_error(
            "fsync failed", std::error_code{errno, std::generic_category()}));
    }
    struct stat st_fd{};
    if (::fstat(fd, &st_fd) != 0) {
        return std::unexpected(system_error(
            "fstat failed", std::error_code{errno, std::generic_category()}));
    }
    struct stat st_path{};
    if (::lstat(file.path.c_str(), &st_path) != 0) {
        return std::unexpected("temporary path cannot be queried with lstat");
    }
    if (st_fd.st_dev != st_path.st_dev || st_fd.st_ino != st_path.st_ino ||
        !S_ISREG(st_path.st_mode)) {
        return std::unexpected(
            "temporary file identity mismatch before publication");
    }

    std::error_code rename_err;
    std::filesystem::rename(file.path, target_path, rename_err);
    if (rename_err) {
        return std::unexpected(rename_err.message());
    }
    file.published = true;
    file.path.clear();
    file.identity.valid = false;
    close_private_file(file);

    auto sync_parent = platform::durability::sync_parent_directory(target_path);
    if (!sync_parent) {
        return std::unexpected("published but parent directory sync failed: " +
                               sync_parent.error());
    }
    return {};
#endif
}

CleanupResult remove_private_file_if_owned(PrivateOutputFile& file) noexcept {
    if (file.is_published() || file.path.empty()) {
        close_private_file(file);
        return CleanupResult::AlreadyAbsent;
    }
    if (!file.identity.valid) {
        close_private_file(file);
        return CleanupResult::IdentityMismatch;
    }

#if defined(_WIN32)
    const auto map_win_err = [](DWORD code) noexcept {
        if (code == ERROR_ACCESS_DENIED || code == ERROR_SHARING_VIOLATION) {
            return CleanupResult::AccessDenied;
        }
        return CleanupResult::FilesystemError;
    };
    if (file.is_open()) {
        HANDLE h = reinterpret_cast<HANDLE>(file.handle.value);
        FILE_DISPOSITION_INFO disp{TRUE};
        const BOOL disp_ok = SetFileInformationByHandle(
            h, FileDispositionInfo, &disp, sizeof(disp));
        const auto disp_err = GetLastError();
        close_private_file(file);
        if (!disp_ok) {
            const auto current_id = query_file_identity(file.path);
            if (current_id.valid && !(current_id == file.identity)) {
                return CleanupResult::IdentityMismatch;
            }
            return map_win_err(disp_err);
        }
        std::error_code exists_err;
        if (std::filesystem::exists(file.path, exists_err)) {
            const auto current_id = query_file_identity(file.path);
            if (!current_id.valid || !(current_id == file.identity)) {
                return CleanupResult::IdentityMismatch;
            }
        }
        return CleanupResult::Removed;
    }

    HANDLE h =
        CreateFileW(file.path.c_str(),
                    DELETE | FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const auto code = GetLastError();
        return (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
                   ? CleanupResult::AlreadyAbsent
                   : map_win_err(code);
    }
    PrivateHandle guard{reinterpret_cast<std::intptr_t>(h)};
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    FILE_ID_INFO current_id{};
    if (!GetFileInformationByHandleEx(
            h, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes &
         (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0 ||
        !GetFileInformationByHandleEx(
            h, FileIdInfo, &current_id, sizeof(current_id)) ||
        !(to_file_identity(current_id) == file.identity)) {
        return CleanupResult::IdentityMismatch;
    }
    FILE_DISPOSITION_INFO disp{TRUE};
    return SetFileInformationByHandle(
               h, FileDispositionInfo, &disp, sizeof(disp))
               ? CleanupResult::Removed
               : map_win_err(GetLastError());
#else
    struct stat st_path{};
    if (::lstat(file.path.c_str(), &st_path) != 0) {
        const auto err = errno;
        close_private_file(file);
        return map_unlink_errno(err);
    }
    bool same = S_ISREG(st_path.st_mode);
    if (file.is_open()) {
        struct stat st_fd{};
        if (::fstat(static_cast<int>(file.handle), &st_fd) != 0) {
            close_private_file(file);
            return CleanupResult::FilesystemError;
        }
        same = same && S_ISREG(st_fd.st_mode) &&
               st_fd.st_dev == st_path.st_dev && st_fd.st_ino == st_path.st_ino;
    } else {
        same = same && to_file_identity(st_path) == file.identity;
    }
    if (!same) {
        close_private_file(file);
        return CleanupResult::IdentityMismatch;
    }
    // shortcut: unlink can race; revisit for adversarial writers.
    const int unlink_res = ::unlink(file.path.c_str());
    const int unlink_err = errno;
    close_private_file(file);
    return unlink_res == 0 ? CleanupResult::Removed
                           : map_unlink_errno(unlink_err);
#endif
}

std::expected<void, std::string>
protect_file(const std::filesystem::path& path) {
    return protect_entry(
        path, false, "empty private file path", "regular file expected at ");
}

std::expected<void, std::string>
write_atomically(const std::filesystem::path& path, std::string_view bytes) {
    if (path.empty() || path.parent_path().empty()) {
        return std::unexpected("invalid private path");
    }
    auto parent = protect_directory(path.parent_path());
    if (!parent) {
        return parent;
    }
    std::error_code target_error;
    const auto target_status =
        std::filesystem::symlink_status(path, target_error);
    if (!target_error &&
        target_status.type() != std::filesystem::file_type::not_found) {
        auto target = protect_file(path);
        if (!target) {
            return target;
        }
    } else if (target_error != std::errc::no_such_file_or_directory) {
        return std::unexpected(
            system_error("could not query destination", target_error));
    }

    for (std::size_t attempt = 0; attempt < 16; ++attempt) {
        auto id = random::hex_id();
        if (!id) {
            return std::unexpected(id.error());
        }
        const auto temporary =
            platform::path::temporary_sibling_path(path, ".", "." + *id);
        auto file = create_private_file(temporary);
        if (!file) {
            if (file.error().is_collision) {
                continue;
            }
            return std::unexpected(file.error().message);
        }
        if (auto written =
                write_private_file(*file, bytes.data(), bytes.size());
            !written) {
            static_cast<void>(remove_private_file_if_owned(*file));
            return written;
        }
        if (auto flushed = flush_and_close_private_file(*file); !flushed) {
            static_cast<void>(remove_private_file_if_owned(*file));
            return flushed;
        }
        if (auto replaced = durability::replace_atomically(temporary, path);
            !replaced) {
            static_cast<void>(remove_private_file_if_owned(*file));
            return replaced;
        }
        return durability::sync_parent_directory(path);
    }
    return std::unexpected("could not reserve temporary file");
}

std::expected<std::uint64_t, StreamError>
stream_regular_file_raw(const std::filesystem::path& path,
                        std::span<std::uint8_t> scratch,
                        bool (*on_chunk)(void*, std::span<const std::uint8_t>),
                        void* context,
                        std::optional<std::uint64_t> expected_size) {
    if (scratch.empty() || on_chunk == nullptr) {
        return make_stream_error(StreamErrorKind::ReadFailed,
                                 "invalid stream buffer or callback");
    }
#if defined(_WIN32)
    const auto handle =
        CreateFileW(path.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT |
                        FILE_FLAG_SEQUENTIAL_SCAN,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const DWORD code = GetLastError();
        const std::error_code sys_err{static_cast<int>(code),
                                      std::system_category()};
        const auto kind =
            (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND)
                ? StreamErrorKind::NotFound
                : StreamErrorKind::OpenFailed;
        return make_stream_error(kind, sys_err.message(), sys_err);
    }
    PrivateHandle guard{reinterpret_cast<std::intptr_t>(handle)};
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!GetFileInformationByHandleEx(
            handle, FileAttributeTagInfo, &attributes, sizeof(attributes))) {
        return make_stream_error(StreamErrorKind::OpenFailed,
                                 "could not query opened file attributes");
    }
    if ((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return make_stream_error(StreamErrorKind::Symlink, "path is a symlink");
    }
    if ((attributes.FileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)) != 0) {
        return make_stream_error(StreamErrorKind::NotRegular,
                                 "path is not a regular file");
    }
    LARGE_INTEGER actual_size{};
    if (!GetFileSizeEx(handle, &actual_size) || actual_size.QuadPart < 0) {
        return make_stream_error(StreamErrorKind::ReadFailed,
                                 "could not read file size");
    }
    if (expected_size &&
        static_cast<std::uint64_t>(actual_size.QuadPart) != *expected_size) {
        return make_stream_error(StreamErrorKind::SizeMismatch,
                                 "file size does not match expected size");
    }

#else
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        const std::error_code sys_err{errno, std::generic_category()};
        const auto kind = errno == ELOOP ? StreamErrorKind::Symlink
                          : (errno == ENOENT || errno == ENOTDIR)
                              ? StreamErrorKind::NotFound
                              : StreamErrorKind::OpenFailed;
        return make_stream_error(kind, sys_err.message(), sys_err);
    }
    PrivateHandle guard{fd};
    struct stat st{};
    if (::fstat(fd, &st) != 0) {
        const std::error_code sys_err{errno, std::generic_category()};
        return make_stream_error(
            StreamErrorKind::OpenFailed, sys_err.message(), sys_err);
    }
    if (!S_ISREG(st.st_mode)) {
        return make_stream_error(StreamErrorKind::NotRegular,
                                 "path is not a regular file");
    }
    if (expected_size &&
        static_cast<std::uint64_t>(st.st_size) != *expected_size) {
        return make_stream_error(StreamErrorKind::SizeMismatch,
                                 "file size does not match expected size");
    }
#endif
    std::uint64_t total_read = 0;
    for (;;) {
#if defined(_WIN32)
        DWORD count = 0;
        if (!ReadFile(handle,
                      scratch.data(),
                      static_cast<DWORD>(scratch.size()),
                      &count,
                      nullptr)) {
            const DWORD code = GetLastError();
            return make_stream_error(
                StreamErrorKind::ReadFailed,
                windows_error("ReadFile failed", code),
                {static_cast<int>(code), std::system_category()});
        }
#else
        const auto count = ::read(fd, scratch.data(), scratch.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            const std::error_code error{errno, std::generic_category()};
            return make_stream_error(
                StreamErrorKind::ReadFailed, error.message(), error);
        }
#endif
        if (count == 0) {
            break;
        }
        const auto chunk_size = static_cast<std::size_t>(count);
        total_read += chunk_size;
        if (!on_chunk(context, scratch.first(chunk_size))) {
            return make_stream_error(StreamErrorKind::Aborted,
                                     "stream aborted by consumer");
        }
    }
    return total_read;
}

bool is_reparse_or_symlink(const std::filesystem::path& path) noexcept {
    if (path.empty()) {
        return false;
    }
#if defined(_WIN32)
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    struct stat status{};
    return ::lstat(path.c_str(), &status) == 0 && S_ISLNK(status.st_mode);
#endif
}

} // namespace kasumi::platform::private_storage

namespace kasumi::platform::path {

std::optional<std::filesystem::path> environment_value(std::string_view name) {
    if (name.empty()) {
        return std::nullopt;
    }
#if defined(_WIN32)
    const auto wide_name = from_utf8(name).native();
    DWORD required = GetEnvironmentVariableW(wide_name.c_str(), nullptr, 0);
    std::wstring buffer;
    while (required > 0) {
        buffer.resize(required);
        const DWORD actual =
            GetEnvironmentVariableW(wide_name.c_str(), buffer.data(), required);
        if (actual == 0) {
            return std::nullopt;
        }
        if (actual < required) {
            buffer.resize(actual);
            if (buffer.empty()) {
                return std::nullopt;
            }
            return std::filesystem::path{std::move(buffer)};
        }
        required = actual;
    }
    return std::nullopt;
#else
    const std::string key{name};
    const char* value = std::getenv(key.c_str());
    if (value == nullptr || *value == '\0') {
        return std::nullopt;
    }
    return std::filesystem::path{value};
#endif
}

} // namespace kasumi::platform::path
