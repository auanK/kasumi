#include "platform/profile_lock.hpp"

#include "platform/private_storage.hpp"

#include <cerrno>
#include <system_error>
#include <utility>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace kasumi::platform {

void release_profile_lock(std::intptr_t& lock) noexcept {
    const auto handle = std::exchange(lock, invalid_profile_lock);
    if (handle == invalid_profile_lock) {
        return;
    }
#ifdef _WIN32
    static_cast<void>(CloseHandle(reinterpret_cast<HANDLE>(handle)));
#else
    static_cast<void>(::close(static_cast<int>(handle)));
#endif
}

std::expected<std::intptr_t, std::string>
acquire_profile_lock(const std::filesystem::path& lock_path) {
    if (lock_path.empty()) {
        return std::unexpected("caminho do lock do perfil vazio");
    }
    auto parent = private_storage::protect_directory(lock_path.parent_path());
    if (!parent) {
        return std::unexpected(parent.error());
    }

#ifdef _WIN32
    const auto handle = CreateFileW(lock_path.c_str(),
                                    GENERIC_READ,
                                    0,
                                    nullptr,
                                    OPEN_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL |
                                        FILE_FLAG_OPEN_REPARSE_POINT,
                                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const auto code = GetLastError();
        if (code == ERROR_SHARING_VIOLATION || code == ERROR_LOCK_VIOLATION) {
            return std::unexpected("perfil já está em uso por outra execução");
        }
        return std::unexpected(
            "não foi possível bloquear o perfil: " +
            std::error_code{static_cast<int>(code), std::system_category()}
                .message());
    }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!GetFileInformationByHandleEx(handle,
                                      FileAttributeTagInfo,
                                      &attributes,
                                      sizeof(attributes)) ||
        (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        const auto code = GetLastError();
        CloseHandle(handle);
        return std::unexpected(
            "lock do perfil não pode ser um reparse point (native_code=" +
            std::to_string(code) + ")");
    }
    auto secured = private_storage::protect_file(lock_path);
    if (!secured) {
        CloseHandle(handle);
        return std::unexpected(secured.error());
    }
    return reinterpret_cast<std::intptr_t>(handle);
#else
    int flags = O_RDONLY | O_CREAT;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int handle = ::open(lock_path.c_str(), flags, 0600);
    if (handle < 0) {
        return std::unexpected(
            "não foi possível abrir o lock do perfil: " +
            std::error_code{errno, std::generic_category()}.message());
    }
    if (::flock(handle, LOCK_EX | LOCK_NB) != 0) {
        const auto code = errno;
        static_cast<void>(::close(handle));
        if (code == EWOULDBLOCK || code == EAGAIN) {
            return std::unexpected("perfil já está em uso por outra execução");
        }
        return std::unexpected(
            "não foi possível bloquear o perfil: " +
            std::error_code{code, std::generic_category()}.message());
    }
    auto secured = private_storage::protect_file(lock_path);
    if (!secured) {
        static_cast<void>(::close(handle));
        return std::unexpected(secured.error());
    }
    return handle;
#endif
}

} // namespace kasumi::platform
