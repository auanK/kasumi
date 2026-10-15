#include "crypto/content.hpp"

#include "content_test.hpp"
#include "platform/path.hpp"

#include <array>
#include <blake3.h>
#include <fstream>
#include <stdexcept>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace kasumi::crypto::content {

std::expected<Hash, std::string> hash_file(const std::filesystem::path& path) {
    try {
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            return std::unexpected("could not open file for hashing: " +
                                   platform::path::to_utf8(path));
        }

        blake3_hasher state;
        blake3_hasher_init(&state);
        std::vector<char> buffer(1024U * 1024U);

        while (input) {
            input.read(buffer.data(),
                       static_cast<std::streamsize>(buffer.size()));
            const auto count = input.gcount();
            if (count > 0) {
                blake3_hasher_update(
                    &state, buffer.data(), static_cast<std::size_t>(count));
            }
        }

        if (input.bad()) {
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

#if defined(_WIN32)
std::expected<Hash, std::string> hash_file_handle(void* handle) {
    return test::hash_file_handle_with_syscalls(handle,
                                                test::HandleHashSyscalls{});
}

std::expected<Hash, std::string>
test::hash_file_handle_with_syscalls(void* handle,
                                     const HandleHashSyscalls& syscalls) {
    const auto win_error = [](std::string_view operation, DWORD error) {
        return std::string{operation} + " failed (Win32 error " +
               std::to_string(error) +
               "): " + std::system_category().message(static_cast<int>(error));
    };

    try {
        HANDLE h = static_cast<HANDLE>(handle);
        LARGE_INTEGER zero{};
        LARGE_INTEGER original{};
        if (!syscalls.seek(h, zero, &original, FILE_CURRENT)) {
            const DWORD error = GetLastError();
            return std::unexpected(win_error("SetFilePointerEx", error));
        }
        if (!syscalls.seek(h, zero, nullptr, FILE_BEGIN)) {
            const DWORD error = GetLastError();
            return std::unexpected(win_error("SetFilePointerEx", error));
        }

        blake3_hasher state;
        blake3_hasher_init(&state);
        std::array<char, 64 * 1024> buffer{};
        for (;;) {
            DWORD bytes_read = 0;
            if (!syscalls.read(h,
                               buffer.data(),
                               static_cast<DWORD>(buffer.size()),
                               &bytes_read,
                               nullptr)) {
                const DWORD error = GetLastError();
                syscalls.seek(h, original, nullptr, FILE_BEGIN);
                return std::unexpected(win_error("ReadFile", error));
            }
            if (bytes_read == 0) {
                break;
            }
            blake3_hasher_update(&state, buffer.data(), bytes_read);
        }

        if (!syscalls.seek(h, original, nullptr, FILE_BEGIN)) {
            const DWORD error = GetLastError();
            return std::unexpected(win_error("SetFilePointerEx", error));
        }

        Hash result{};
        blake3_hasher_finalize(&state,
                               reinterpret_cast<std::uint8_t*>(result.data()),
                               result.size());
        return result;
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"could not compute handle hash: "} +
                               exception.what());
    }
}
#endif

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
        std::error_code error;
        const auto file_status = std::filesystem::symlink_status(path, error);
        if (error) {
            return std::unexpected("could not query file: " + error.message());
        }
        if (std::filesystem::is_symlink(file_status)) {
            return std::unexpected("path is a symlink and cannot be verified");
        }
        if (file_status.type() == std::filesystem::file_type::not_found) {
            return std::unexpected("file does not exist");
        }
        if (!std::filesystem::is_regular_file(file_status)) {
            return std::unexpected("path is not a regular file");
        }

        if (expected_size) {
            const auto actual_size = std::filesystem::file_size(path, error);
            if (error) {
                return std::unexpected("could not read file size: " +
                                       error.message());
            }
            if (actual_size != *expected_size) {
                return std::unexpected(
                    "file size does not match expected size");
            }
        }

        auto actual_hash = hash_file(path);
        if (!actual_hash) {
            return std::unexpected(actual_hash.error());
        }
        if (*actual_hash != *decoded_hash) {
            return std::unexpected("file content does not match expected hash");
        }
        return {};
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"could not verify file: "} +
                               exception.what());
    }
}

} // namespace kasumi::crypto::content
