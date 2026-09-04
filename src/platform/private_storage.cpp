#include "platform/private_storage.hpp"

#include "platform/durability.hpp"
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
            windows_error("OpenProcessToken falhou", GetLastError()));
    }

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<std::byte> token_data(size);
    if (size == 0 || !GetTokenInformation(
                         token, TokenUser, token_data.data(), size, &size)) {
        const auto code = GetLastError();
        CloseHandle(token);
        return std::unexpected(
            windows_error("GetTokenInformation falhou", code));
    }
    CloseHandle(token);

    wchar_t* sid_text = nullptr;
    const auto* token_user =
        reinterpret_cast<const TOKEN_USER*>(token_data.data());
    if (!ConvertSidToStringSidW(token_user->User.Sid, &sid_text)) {
        return std::unexpected(
            windows_error("ConvertSidToStringSidW falhou", GetLastError()));
    }
    std::wstring sid;
    try {
        sid = sid_text;
    } catch (...) {
        LocalFree(sid_text);
        return std::unexpected("não foi possível copiar o SID do usuário");
    }
    LocalFree(sid_text);
    const std::wstring inherit = directory ? L"OICI" : L"";
    const std::wstring sddl = L"D:P(A;" + inherit + L";FA;;;SY)(A;" + inherit +
                              L";FA;;;" + sid + L")";

    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        return std::unexpected(windows_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW falhou",
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
            windows_error("GetSecurityDescriptorDacl falhou", GetLastError());
        LocalFree(*descriptor);
        return std::unexpected(error);
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
    LocalFree(*descriptor);
    if (result != ERROR_SUCCESS) {
        return std::unexpected(
            windows_error("SetNamedSecurityInfoW falhou", result));
    }
    return {};
}

std::expected<DWORD, std::string>
checked_attributes(const std::filesystem::path& path) {
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return std::unexpected(
            windows_error("GetFileAttributesW falhou", GetLastError()));
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return std::unexpected("reparse point não é permitido em '" +
                               path.string() + "'");
    }
    return attributes;
}

#else

std::expected<struct stat, std::string>
checked_status(const std::filesystem::path& path) {
    struct stat status{};
    if (::lstat(path.c_str(), &status) != 0) {
        return std::unexpected(system_error(
            "lstat falhou", std::error_code{errno, std::generic_category()}));
    }
    if (S_ISLNK(status.st_mode)) {
        return std::unexpected("link simbólico não é permitido em '" +
                               path.string() + "'");
    }
    return status;
}

#endif

void remove_temporary(const std::filesystem::path& path) noexcept {
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

} // namespace

std::expected<void, std::string>
create_directory(const std::filesystem::path& path) {
    if (path.empty()) {
        return std::unexpected("diretório privado vazio");
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
            windows_error("CreateDirectoryW falhou", GetLastError());
        LocalFree(*descriptor);
        return std::unexpected(error);
    }
    LocalFree(*descriptor);
#else
    if (::mkdir(path.c_str(), 0700) != 0) {
        return std::unexpected(system_error(
            "mkdir falhou", std::error_code{errno, std::generic_category()}));
    }
#endif
    return {};
}

std::expected<void, std::string>
protect_directory(const std::filesystem::path& path) {
    if (path.empty()) {
        return std::unexpected("diretório privado vazio");
    }
#if defined(_WIN32)
    auto attributes = checked_attributes(path);
    if (!attributes) {
        return std::unexpected(attributes.error());
    }
    if ((*attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        return std::unexpected("diretório esperado em '" + path.string() + "'");
    }
    return apply_acl(path, true);
#else
    auto status = checked_status(path);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (!S_ISDIR(status->st_mode)) {
        return std::unexpected("diretório esperado em '" + path.string() + "'");
    }
    if (::chmod(path.c_str(), 0700) != 0) {
        return std::unexpected(
            system_error("chmod 0700 falhou",
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
        return std::unexpected(system_error("symlink_status falhou", error));
    }
    if (status.type() == std::filesystem::file_type::not_found) {
        return private_storage::create_directory(path);
    }
    return protect_directory(path);
}

std::expected<void, std::string>
protect_tree(const std::filesystem::path& root) {
    auto protected_root = protect_directory(root);
    if (!protected_root) {
        return protected_root;
    }
    std::error_code error;
    std::filesystem::recursive_directory_iterator entries(root, error);
    if (error) {
        return std::unexpected(system_error(
            "não foi possível listar '" + root.string() + "'", error));
    }
    const std::filesystem::recursive_directory_iterator end;
    while (entries != end) {
        const auto path = entries->path();
        const auto status = std::filesystem::symlink_status(path, error);
        if (error) {
            return std::unexpected(system_error(
                "não foi possível consultar '" + path.string() + "'", error));
        }
        if (std::filesystem::is_symlink(status)) {
            return std::unexpected("link não é permitido em '" + path.string() +
                                   "'");
        }
        std::expected<void, std::string> protected_path;
        if (std::filesystem::is_directory(status)) {
            protected_path = protect_directory(path);
        } else if (std::filesystem::is_regular_file(status)) {
            protected_path = protect_file(path);
        } else {
            return std::unexpected("objeto interno inválido em '" +
                                   path.string() + "'");
        }
        if (!protected_path) {
            return protected_path;
        }
        entries.increment(error);
        if (error) {
            return std::unexpected(system_error(
                "não foi possível listar '" + root.string() + "'", error));
        }
    }
    return {};
}

std::expected<void, std::string>
create_file(const std::filesystem::path& path) {
    if (path.empty()) {
        return std::unexpected("arquivo privado vazio");
    }
#if defined(_WIN32)
    auto descriptor = security_descriptor(false);
    if (!descriptor) {
        return std::unexpected(descriptor.error());
    }
    SECURITY_ATTRIBUTES attributes{
        .nLength = sizeof(SECURITY_ATTRIBUTES),
        .lpSecurityDescriptor = *descriptor,
        .bInheritHandle = FALSE,
    };
    const auto file = CreateFileW(path.c_str(),
                                  GENERIC_READ | GENERIC_WRITE,
                                  0,
                                  &attributes,
                                  CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL,
                                  nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        const auto error = windows_error("CreateFileW falhou", GetLastError());
        LocalFree(*descriptor);
        return std::unexpected(error);
    }
    LocalFree(*descriptor);
    if (!CloseHandle(file)) {
        return std::unexpected(
            windows_error("CloseHandle falhou", GetLastError()));
    }
#else
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int file = ::open(path.c_str(), flags, 0600);
    if (file < 0) {
        return std::unexpected(system_error(
            "open falhou", std::error_code{errno, std::generic_category()}));
    }
    if (::fchmod(file, 0600) != 0) {
        const auto error = errno;
        ::close(file);
        remove_temporary(path);
        return std::unexpected(
            system_error("fchmod 0600 falhou",
                         std::error_code{error, std::generic_category()}));
    }
    if (::close(file) != 0) {
        return std::unexpected(system_error(
            "close falhou", std::error_code{errno, std::generic_category()}));
    }
#endif
    return {};
}

std::expected<void, std::string>
protect_file(const std::filesystem::path& path) {
    if (path.empty()) {
        return std::unexpected("arquivo privado vazio");
    }
#if defined(_WIN32)
    auto attributes = checked_attributes(path);
    if (!attributes) {
        return std::unexpected(attributes.error());
    }
    if ((*attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        return std::unexpected("arquivo regular esperado em '" + path.string() +
                               "'");
    }
    return apply_acl(path, false);
#else
    auto status = checked_status(path);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (!S_ISREG(status->st_mode)) {
        return std::unexpected("arquivo regular esperado em '" + path.string() +
                               "'");
    }
    if (::chmod(path.c_str(), 0600) != 0) {
        return std::unexpected(
            system_error("chmod 0600 falhou",
                         std::error_code{errno, std::generic_category()}));
    }
    return {};
#endif
}

std::expected<void, std::string>
write_atomically(const std::filesystem::path& path, std::string_view bytes) {
    if (path.empty() || path.parent_path().empty()) {
        return std::unexpected("caminho privado inválido");
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
            system_error("não foi possível consultar o destino", target_error));
    }

    for (std::size_t attempt = 0; attempt < 16; ++attempt) {
        auto id = random::hex_id();
        if (!id) {
            return std::unexpected(id.error());
        }
        const auto temporary =
            path.parent_path() / ("." + path.filename().string() + "." + *id);
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
            return std::unexpected("falha ao escrever arquivo privado");
        }
        output.close();
        if (output.fail()) {
            remove_temporary(temporary);
            return std::unexpected("falha ao fechar arquivo privado");
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
    return std::unexpected("não foi possível reservar arquivo temporário");
}

} // namespace kasumi::platform::private_storage
