#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"

#include "platform/durability.hpp"
#include "platform/path.hpp"
#include "platform/random.hpp"

#include <cerrno>
#include <cstddef>
#include <fstream>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <aclapi.h>
#include <sddl.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace kasumi::platform::private_storage {
namespace {

std::string system_error(std::string_view operation,
                         const std::error_code& error) {
    return std::string{operation} + ": " + error.message();
}

#if defined(_WIN32)

std::string windows_error(std::string_view operation, DWORD code) {
    return system_error(
        operation,
        std::error_code{static_cast<int>(code), std::system_category()});
}

std::expected<PSECURITY_DESCRIPTOR, std::string>
security_descriptor(bool directory) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return std::unexpected(
            windows_error("OpenProcessToken failed", GetLastError()));
    }

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<std::byte> token_data(size);
    if (size == 0 || !GetTokenInformation(
                         token, TokenUser, token_data.data(), size, &size)) {
        const auto code = GetLastError();
        CloseHandle(token);
        return std::unexpected(
            windows_error("GetTokenInformation failed", code));
    }
    CloseHandle(token);

    wchar_t* sid_text = nullptr;
    const auto* token_user =
        reinterpret_cast<const TOKEN_USER*>(token_data.data());
    if (!ConvertSidToStringSidW(token_user->User.Sid, &sid_text)) {
        return std::unexpected(
            windows_error("ConvertSidToStringSidW failed", GetLastError()));
    }
    std::wstring sid;
    try {
        sid = sid_text;
    } catch (...) {
        LocalFree(sid_text);
        return std::unexpected("could not copy user SID");
    }
    LocalFree(sid_text);
    const std::wstring inherit = directory ? L"OICI" : L"";
    const std::wstring sddl = L"D:P(A;" + inherit + L";FA;;;SY)(A;" + inherit +
                              L";FA;;;" + sid + L")";

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        return std::unexpected(windows_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed",
            GetLastError()));
    }
    return descriptor;
}

std::expected<void, std::string> apply_acl(const std::filesystem::path& path,
                                           bool directory) {
    auto descriptor = security_descriptor(directory);
    if (!descriptor) {
        return std::unexpected(descriptor.error());
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    if (!GetSecurityDescriptorDacl(*descriptor, &present, &dacl, &defaulted) ||
        !present) {
        const auto error =
            windows_error("GetSecurityDescriptorDacl failed", GetLastError());
        LocalFree(*descriptor);
        return std::unexpected(error);
    }
    platform::perf_trace::count("apply_acl calls");
    const auto acl_trace = platform::perf_trace::begin();
    auto writable = path.wstring();
    const auto result = SetNamedSecurityInfoW(
        writable.data(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        dacl,
        nullptr);
    platform::perf_trace::finish("apply_acl wall", acl_trace);
    LocalFree(*descriptor);
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

void remove_temporary(const std::filesystem::path& path) noexcept {
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

#if defined(_WIN32)
std::expected<void, std::string>
protect_windows_tree(const std::filesystem::path& root) {
    auto protected_root = protect_directory(root);
    if (!protected_root) {
        return protected_root;
    }

    std::vector<std::filesystem::path> directories{root};
    while (!directories.empty()) {
        auto directory = std::move(directories.back());
        directories.pop_back();
        WIN32_FIND_DATAW entry{};
        auto pattern = directory.native();
        pattern.append(L"\\*");
        const auto search = FindFirstFileW(pattern.c_str(), &entry);
        if (search == INVALID_HANDLE_VALUE) {
            const auto code = GetLastError();
            if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
                continue;
            }
            return std::unexpected(
                windows_error("FindFirstFileW failed for '" +
                                  platform::path::to_utf8(directory) + "'",
                              code));
        }

        std::string failure;
        do {
            const std::wstring_view name{entry.cFileName};
            if (name == L"." || name == L"..") {
                continue;
            }
            auto native_path = directory.native();
            native_path.push_back(L'\\');
            native_path.append(entry.cFileName);
            const std::filesystem::path path{std::move(native_path)};
            if ((entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                failure = "reparse point is not allowed in '" +
                          platform::path::to_utf8(path) + "'";
                break;
            }

            std::expected<void, std::string> secured;
            if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                secured = protect_directory(path);
                directories.push_back(path);
            } else if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == 0) {
                secured = protect_file(path);
            } else {
                failure = "invalid internal object in '" +
                          platform::path::to_utf8(path) + "'";
                break;
            }
            if (!secured) {
                failure = secured.error();
                break;
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
                windows_error("FindNextFileW failed for '" +
                                  platform::path::to_utf8(directory) + "'",
                              enumeration_error));
        }
    }
    return {};
}
#endif

} // namespace

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
        .lpSecurityDescriptor = *descriptor,
        .bInheritHandle = FALSE,
    };
    if (!CreateDirectoryW(path.c_str(), &attributes)) {
        const auto error =
            windows_error("CreateDirectoryW failed", GetLastError());
        LocalFree(*descriptor);
        return std::unexpected(error);
    }
    LocalFree(*descriptor);
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
    if (path.empty()) {
        return std::unexpected("empty private directory path");
    }
#if defined(_WIN32)
    auto attributes = checked_attributes(path);
    if (!attributes) {
        return std::unexpected(attributes.error());
    }
    if ((*attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        return std::unexpected("directory expected at '" +
                               platform::path::to_utf8(path) + "'");
    }
    return apply_acl(path, true);
#else
    auto status = checked_status(path);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (!S_ISDIR(status->st_mode)) {
        return std::unexpected("directory expected at '" +
                               platform::path::to_utf8(path) + "'");
    }
    if (::chmod(path.c_str(), 0700) != 0) {
        return std::unexpected(
            system_error("chmod 0700 failed",
                         std::error_code{errno, std::generic_category()}));
    }
    return {};
#endif
}

std::expected<void, std::string>
ensure_directory(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory) {
        return private_storage::create_directory(path);
    }
    if (error) {
        return std::unexpected(system_error("symlink_status failed", error));
    }
    if (status.type() == std::filesystem::file_type::not_found) {
        return private_storage::create_directory(path);
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
        .lpSecurityDescriptor = *descriptor,
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
    LocalFree(*descriptor);
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
    FileIdentity identity{};
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
    identity.volume_or_dev = id.VolumeSerialNumber;
    std::memcpy(
        &identity.file_id_low, id.FileId.Identifier, sizeof(std::uint64_t));
    std::memcpy(&identity.file_id_high,
                id.FileId.Identifier + sizeof(std::uint64_t),
                sizeof(std::uint64_t));
    identity.valid = true;
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
        std::string cleanup_detail;
        struct stat st_f{};
        struct stat st_path{};
        if (::fstat(file, &st_f) == 0 && ::lstat(path.c_str(), &st_path) == 0 &&
            st_f.st_dev == st_path.st_dev && st_f.st_ino == st_path.st_ino &&
            S_ISREG(st_path.st_mode)) {
            if (::unlink(path.c_str()) != 0) {
                const auto unlink_err = errno;
                cleanup_detail = " (cleanup unlink failed: " +
                    std::error_code{unlink_err, std::generic_category()}.message() + ")";
            }
        }
        ::close(file);
        return std::unexpected(CreateFileError{
            system_error("fchmod 0600 failed" + cleanup_detail,
                         std::error_code{error, std::generic_category()}),
            false});
    }
    struct stat st{};
    FileIdentity identity{};
    const int fstat_res = ::fstat(file, &st);
    if (fstat_res != 0) {
        const auto error = errno;
        std::string cleanup_detail;
        struct stat st_path{};
        if (::lstat(path.c_str(), &st_path) == 0 && S_ISREG(st_path.st_mode)) {
            if (::unlink(path.c_str()) != 0) {
                const auto unlink_err = errno;
                cleanup_detail = " (cleanup unlink failed: " +
                    std::error_code{unlink_err, std::generic_category()}.message() + ")";
            }
        }
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
    const HANDLE handle_to_close =
        reinterpret_cast<HANDLE>(
            std::exchange(
                file.handle.value,
                invalid_private_handle));
    if (!CloseHandle(handle_to_close)) {
        const auto error = GetLastError();
        return std::unexpected(windows_error("CloseHandle failed", error));
    }
    return {};
#else
    int fd = static_cast<int>(file.handle);
    if (fsync(fd) != 0) {
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

FileIdentity query_file_identity(const std::filesystem::path& path) noexcept {
    if (path.empty()) {
        return {};
    }
#if defined(_WIN32)
    const DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES ||
        (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return {};
    }
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
    FILE_ID_INFO id{};
    FileIdentity result{};
    if (GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id))) {
        result.volume_or_dev = id.VolumeSerialNumber;
        std::memcpy(
            &result.file_id_low, id.FileId.Identifier, sizeof(std::uint64_t));
        std::memcpy(&result.file_id_high,
                    id.FileId.Identifier + sizeof(std::uint64_t),
                    sizeof(std::uint64_t));
        result.valid = true;
    }
    CloseHandle(handle);
    return result;
#else
    struct stat st{};
    if (::lstat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        return {};
    }
    FileIdentity result{};
    result.volume_or_dev = static_cast<std::uint64_t>(st.st_dev);
    result.file_id_low = static_cast<std::uint64_t>(st.st_ino);
    result.valid = true;
    return result;
#endif
}

DirectoryIdentity
query_directory_identity(const std::filesystem::path& path) noexcept {
    if (path.empty()) {
        return {};
    }
#if defined(_WIN32)
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
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    FILE_ID_INFO id{};
    DirectoryIdentity result{};
    if (GetFileInformationByHandleEx(
            handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) &&
        (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
        GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id))) {
        result.volume_or_dev = id.VolumeSerialNumber;
        std::memcpy(
            &result.file_id_low, id.FileId.Identifier, sizeof(std::uint64_t));
        std::memcpy(&result.file_id_high,
                    id.FileId.Identifier + sizeof(std::uint64_t),
                    sizeof(std::uint64_t));
        result.valid = true;
    }
    CloseHandle(handle);
    return result;
#else
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW
#ifdef O_CLOEXEC
                                  | O_CLOEXEC
#endif
    );
    if (descriptor < 0) {
        return {};
    }
    struct stat status{};
    DirectoryIdentity result{};
    if (::fstat(descriptor, &status) == 0 && S_ISDIR(status.st_mode)) {
        result.volume_or_dev = static_cast<std::uint64_t>(status.st_dev);
        result.file_id_low = static_cast<std::uint64_t>(status.st_ino);
        result.valid = true;
    }
    static_cast<void>(::close(descriptor));
    return result;
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
    FileIdentity handle_id{
        .volume_or_dev = current_id.VolumeSerialNumber,
        .file_id_low = 0,
        .file_id_high = 0,
        .valid = true,
    };
    std::memcpy(&handle_id.file_id_low,
                current_id.FileId.Identifier,
                sizeof(std::uint64_t));
    std::memcpy(&handle_id.file_id_high,
                current_id.FileId.Identifier + sizeof(std::uint64_t),
                sizeof(std::uint64_t));
    if (!(handle_id == file.identity)) {
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
    if (fsync(fd) != 0) {
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
        if (file.is_open()) {
            close_private_file(file);
        }
        return CleanupResult::AlreadyAbsent;
    }

    if (!file.identity.valid) {
        if (file.is_open()) {
            close_private_file(file);
        }
        return CleanupResult::IdentityMismatch;
    }

    if (file.is_open()) {
#if defined(_WIN32)
        HANDLE h = reinterpret_cast<HANDLE>(file.handle.value);
        FILE_DISPOSITION_INFO disp{TRUE};
        const BOOL disp_ok = SetFileInformationByHandle(
            h, FileDispositionInfo, &disp, sizeof(disp));
        const auto disp_err = GetLastError();
        close_private_file(file);
        if (!disp_ok) {
            if (!file.path.empty()) {
                const auto current_id = query_file_identity(file.path);
                if (current_id.valid && !(current_id == file.identity)) {
                    return CleanupResult::IdentityMismatch;
                }
            }
            if (disp_err == ERROR_ACCESS_DENIED ||
                disp_err == ERROR_SHARING_VIOLATION) {
                return CleanupResult::AccessDenied;
            }
            return CleanupResult::FilesystemError;
        }
        if (!file.path.empty()) {
            std::error_code exists_err;
            if (std::filesystem::exists(file.path, exists_err)) {
                const auto current_id = query_file_identity(file.path);
                if (!current_id.valid || !(current_id == file.identity)) {
                    return CleanupResult::IdentityMismatch;
                }
            }
        }
        return CleanupResult::Removed;
#else
        int fd = static_cast<int>(file.handle);
        struct stat st_fd{};
        if (::fstat(fd, &st_fd) != 0) {
            close_private_file(file);
            return CleanupResult::FilesystemError;
        }
        struct stat st_path{};
        if (::lstat(file.path.c_str(), &st_path) != 0) {
            const auto err = errno;
            close_private_file(file);
            if (err == ENOENT) {
                return CleanupResult::AlreadyAbsent;
            }
            return CleanupResult::FilesystemError;
        }
        if (st_fd.st_dev != st_path.st_dev || st_fd.st_ino != st_path.st_ino ||
            !S_ISREG(st_path.st_mode)) {
            close_private_file(file);
            return CleanupResult::IdentityMismatch;
        }

        if (::unlink(file.path.c_str()) != 0) {
            const auto err = errno;
            close_private_file(file);
            if (err == ENOENT) {
                return CleanupResult::AlreadyAbsent;
            }
            if (err == EACCES || err == EPERM || err == EROFS) {
                return CleanupResult::AccessDenied;
            }
            return CleanupResult::FilesystemError;
        }
        close_private_file(file);
        return CleanupResult::Removed;
#endif
    }

    if (file.path.empty()) {
        return CleanupResult::AlreadyAbsent;
    }
    std::error_code exists_err;
    const bool exists = std::filesystem::exists(file.path, exists_err);
    if (exists_err) {
        return CleanupResult::FilesystemError;
    }
    if (!exists) {
        return CleanupResult::AlreadyAbsent;
    }
    if (!file.identity.valid) {
        return CleanupResult::IdentityMismatch;
    }

#if defined(_WIN32)
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
        if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
            return CleanupResult::AlreadyAbsent;
        }
        if (code == ERROR_ACCESS_DENIED || code == ERROR_SHARING_VIOLATION) {
            return CleanupResult::AccessDenied;
        }
        return CleanupResult::FilesystemError;
    }

    FILE_ID_INFO current_id{};
    if (!GetFileInformationByHandleEx(
            h, FileIdInfo, &current_id, sizeof(current_id))) {
        CloseHandle(h);
        return CleanupResult::IdentityMismatch;
    }
    FileIdentity id{
        .volume_or_dev = current_id.VolumeSerialNumber,
        .file_id_low = 0,
        .file_id_high = 0,
        .valid = true,
    };
    std::memcpy(
        &id.file_id_low, current_id.FileId.Identifier, sizeof(std::uint64_t));
    std::memcpy(&id.file_id_high,
                current_id.FileId.Identifier + sizeof(std::uint64_t),
                sizeof(std::uint64_t));
    if (!(id == file.identity)) {
        CloseHandle(h);
        return CleanupResult::IdentityMismatch;
    }

    FILE_DISPOSITION_INFO disp{TRUE};
    if (!SetFileInformationByHandle(
            h, FileDispositionInfo, &disp, sizeof(disp))) {
        const auto code = GetLastError();
        CloseHandle(h);
        if (code == ERROR_ACCESS_DENIED || code == ERROR_SHARING_VIOLATION) {
            return CleanupResult::AccessDenied;
        }
        return CleanupResult::FilesystemError;
    }
    CloseHandle(h);
    return CleanupResult::Removed;
#else
    const auto current_id = query_file_identity(file.path);
    if (!current_id.valid || !(current_id == file.identity)) {
        return CleanupResult::IdentityMismatch;
    }

    std::error_code remove_err;
    const bool removed = std::filesystem::remove(file.path, remove_err);
    if (removed && !remove_err) {
        return CleanupResult::Removed;
    }
    if (remove_err == std::errc::no_such_file_or_directory) {
        return CleanupResult::AlreadyAbsent;
    }
    if (remove_err == std::errc::permission_denied) {
        return CleanupResult::AccessDenied;
    }
    return CleanupResult::FilesystemError;
#endif
}

std::expected<void, std::string>
protect_file(const std::filesystem::path& path) {
    if (path.empty()) {
        return std::unexpected("empty private file path");
    }
#if defined(_WIN32)
    auto attributes = checked_attributes(path);
    if (!attributes) {
        return std::unexpected(attributes.error());
    }
    if ((*attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        return std::unexpected("regular file expected at '" +
                               platform::path::to_utf8(path) + "'");
    }
    return apply_acl(path, false);
#else
    auto status = checked_status(path);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (!S_ISREG(status->st_mode)) {
        return std::unexpected("regular file expected at '" +
                               platform::path::to_utf8(path) + "'");
    }
    if (::chmod(path.c_str(), 0600) != 0) {
        return std::unexpected(
            system_error("chmod 0600 failed",
                         std::error_code{errno, std::generic_category()}));
    }
    return {};
#endif
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
        auto created = create_file(temporary);
        if (!created) {
            std::error_code exists_error;
            if (std::filesystem::exists(temporary, exists_error) &&
                !exists_error) {
                continue;
            }
            return created;
        }

        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output ||
            (!bytes.empty() &&
             !output.write(bytes.data(),
                           static_cast<std::streamsize>(bytes.size()))) ||
            !output.flush()) {
            output.close();
            remove_temporary(temporary);
            return std::unexpected("failed to write private file");
        }
        output.close();
        if (output.fail()) {
            remove_temporary(temporary);
            return std::unexpected("failed to close private file");
        }
        auto synced = durability::sync_file(temporary);
        if (!synced) {
            remove_temporary(temporary);
            return synced;
        }
        auto replaced = durability::replace_atomically(temporary, path);
        if (!replaced) {
            remove_temporary(temporary);
            return replaced;
        }
        return durability::sync_parent_directory(path);
    }
    return std::unexpected("could not reserve temporary file");
}

} // namespace kasumi::platform::private_storage
