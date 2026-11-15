#include "crypto/content.hpp"

#include "crypto/secure_memory.hpp"
#include "platform/path.hpp"

#include <blake3.h>
#include <cerrno>
#include <cstdint>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <system_error>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace kasumi::crypto::content {

namespace {

struct BufferWipeGuard {
    void* data = nullptr;
    std::size_t size = 0;

    ~BufferWipeGuard() noexcept {
        if (data != nullptr && size > 0) {
            secure_memory::wipe(data, size);
        }
    }
};

} // namespace

std::expected<Hash, std::string> hash_file(const std::filesystem::path& path) {
    try {
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            return std::unexpected("could not open file for hashing: " +
                                   platform::path::to_utf8(path));
        }

        blake3_hasher state;
        blake3_hasher_init(&state);
        BufferWipeGuard state_guard{&state, sizeof(state)};
        constexpr std::size_t buffer_size = 64U * 1024U;
        auto buffer = std::make_unique_for_overwrite<char[]>(buffer_size);
        BufferWipeGuard wipe_guard{buffer.get(), buffer_size};

        while (input) {
            input.read(buffer.get(), static_cast<std::streamsize>(buffer_size));
            const auto count = input.gcount();
            if (count > 0) {
                blake3_hasher_update(
                    &state, buffer.get(), static_cast<std::size_t>(count));
            }
        }

        if (input.bad() || (input.fail() && !input.eof())) {
            return std::unexpected("failed to read file for hashing: " +
                                   platform::path::to_utf8(path));
        }

        Hash result{};
        blake3_hasher_finalize(&state,
                               reinterpret_cast<std::uint8_t*>(result.data()),
                               result.size());
        return result;
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"could not compute file hash: "} +
                               exception.what());
    }
}

std::expected<void, std::string>
verify_file(const std::filesystem::path& path,
            std::string_view expected_hash,
            std::optional<std::uint64_t> expected_size) {
    auto decoded_hash = hash_from_hex(expected_hash);
    if (!decoded_hash) {
        return std::unexpected("invalid expected hash: " +
                               decoded_hash.error());
    }

    try {
        constexpr std::size_t buffer_size = 64U * 1024U;
        auto buffer = std::make_unique_for_overwrite<char[]>(buffer_size);
        BufferWipeGuard wipe_guard{buffer.get(), buffer_size};
        blake3_hasher state;
        blake3_hasher_init(&state);
        BufferWipeGuard state_guard{&state, sizeof(state)};

#if defined(_WIN32)
        const auto handle = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT |
                FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            const DWORD err = GetLastError();
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
                return std::unexpected("file does not exist");
            }
            return std::unexpected(
                "could not open file for verification: " +
                std::system_category().message(static_cast<int>(err)));
        }
        struct HandleGuard {
            HANDLE h;
            ~HandleGuard() noexcept {
                CloseHandle(h);
            }
        } handle_guard{handle};

        FILE_ATTRIBUTE_TAG_INFO attributes{};
        if (!GetFileInformationByHandleEx(handle,
                                          FileAttributeTagInfo,
                                          &attributes,
                                          sizeof(attributes))) {
            return std::unexpected("could not query opened file attributes");
        }
        if ((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            return std::unexpected("path is a symlink and cannot be verified");
        }
        if ((attributes.FileAttributes &
             (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)) != 0) {
            return std::unexpected("path is not a regular file");
        }
        LARGE_INTEGER actual_size{};
        if (!GetFileSizeEx(handle, &actual_size) || actual_size.QuadPart < 0) {
            return std::unexpected("could not read file size");
        }
        if (expected_size && static_cast<std::uint64_t>(actual_size.QuadPart) !=
                                 *expected_size) {
            return std::unexpected("file size does not match expected size");
        }
        for (;;) {
            DWORD count = 0;
            if (!ReadFile(handle,
                          buffer.get(),
                          static_cast<DWORD>(buffer_size),
                          &count,
                          nullptr)) {
                return std::unexpected("failed to read file for hashing: " +
                                       platform::path::to_utf8(path));
            }
            if (count == 0) {
                break;
            }
            blake3_hasher_update(
                &state, buffer.get(), static_cast<std::size_t>(count));
        }
#else
        const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            if (errno == ELOOP) {
                return std::unexpected(
                    "path is a symlink and cannot be verified");
            }
            if (errno == ENOENT || errno == ENOTDIR) {
                return std::unexpected("file does not exist");
            }
            return std::unexpected(
                "could not query file: " +
                std::error_code{errno, std::generic_category()}.message());
        }
        struct FdGuard {
            int fd;
            ~FdGuard() noexcept {
                ::close(fd);
            }
        } fd_guard{fd};

        struct stat st{};
        if (::fstat(fd, &st) != 0) {
            return std::unexpected(
                "could not query file: " +
                std::error_code{errno, std::generic_category()}.message());
        }
        if (!S_ISREG(st.st_mode)) {
            return std::unexpected("path is not a regular file");
        }
        if (expected_size &&
            static_cast<std::uint64_t>(st.st_size) != *expected_size) {
            return std::unexpected("file size does not match expected size");
        }
        for (;;) {
            const auto count = ::read(fd, buffer.get(), buffer_size);
            if (count == 0) {
                break;
            }
            if (count < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return std::unexpected("failed to read file for hashing: " +
                                       platform::path::to_utf8(path));
            }
            blake3_hasher_update(
                &state, buffer.get(), static_cast<std::size_t>(count));
        }
#endif

        Hash actual_hash{};
        blake3_hasher_finalize(
            &state,
            reinterpret_cast<std::uint8_t*>(actual_hash.data()),
            actual_hash.size());
        if (actual_hash != *decoded_hash) {
            return std::unexpected("file content does not match expected hash");
        }
        return {};
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"could not verify file: "} +
                               exception.what());
    }
}

} // namespace kasumi::crypto::content
