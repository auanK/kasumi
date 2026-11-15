#include "runtime/vault.hpp"

#include "platform/durability.hpp"
#include "platform/private_storage.hpp"

#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <monocypher.h>
#include <string_view>

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

namespace kasumi::runtime::vault {

constexpr std::string_view MAGIC = "KASUMI_EDGE_SYNC_V1_MASK";

std::expected<KeyBytes, runtime::Error> decode_hex(std::string_view text) {
    if (text.size() != KEY_SIZE * 2) {
        return std::unexpected(Error{
            .code = ErrorCode::KeyInvalid,
            .detail = "KASUMI_MASTER_KEY must be 64 hexadecimal characters"});
    }
    const auto digit = [](char value) -> int {
        if (value >= '0' && value <= '9')
            return value - '0';
        if (value >= 'a' && value <= 'f')
            return value - 'a' + 10;
        if (value >= 'A' && value <= 'F')
            return value - 'A' + 10;
        return -1;
    };
    KeyBytes key{};
    bool success = false;
    struct KeyWipeGuard {
        KeyBytes& value;
        bool& success;
        ~KeyWipeGuard() noexcept {
            if (!success) {
                crypto_wipe(value.data(), value.size());
            }
        }
    } guard{key, success};
    for (std::size_t index = 0; index < key.size(); ++index) {
        const int high = digit(text[index * 2]);
        const int low = digit(text[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return std::unexpected(Error{
                .code = ErrorCode::KeyInvalid,
                .detail =
                    "KASUMI_MASTER_KEY contains non-hexadecimal character"});
        }
        key[index] = static_cast<uint8_t>((high << 4) | low);
    }
    success = true;
    return key;
}

void obscure(std::span<std::uint8_t, KEY_SIZE> key) {
    for (std::size_t i = 0; i < KEY_SIZE; ++i) {
        key[i] ^= static_cast<uint8_t>(MAGIC[i % MAGIC.size()]);
    }
}

std::expected<KeyBytes, runtime::Error>
read_impl(const std::filesystem::path& path, bool protect) {
    if (protect) {
        auto secured = platform::private_storage::protect_file(path);
        if (!secured) {
            return std::unexpected(Error{.code = ErrorCode::KeyNotFound,
                                         .detail = secured.error()});
        }
    } else {
        std::error_code filesystem_error;
        const auto status =
            std::filesystem::symlink_status(path, filesystem_error);
        if (filesystem_error ||
            status.type() == std::filesystem::file_type::not_found ||
            std::filesystem::is_symlink(status) ||
            !std::filesystem::is_regular_file(status)) {
            return std::unexpected(
                Error{.code = ErrorCode::KeyNotFound,
                      .detail = "key.bin file is missing or invalid"});
        }
    }
    KeyBytes key{};
    bool success = false;
    struct KeyWipeGuard {
        KeyBytes& value;
        bool& success;
        ~KeyWipeGuard() noexcept {
            if (!success) {
                crypto_wipe(value.data(), value.size());
            }
        }
    } guard{key, success};

    std::array<char, KEY_SIZE + 1> buf{};
    std::size_t total = 0;
    struct BufWipeGuard {
        std::array<char, KEY_SIZE + 1>& buf;
        ~BufWipeGuard() noexcept {
            crypto_wipe(buf.data(), buf.size());
        }
    } buf_guard{buf};

#if defined(_WIN32)
    const auto native =
        CreateFileW(path.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN,
                    nullptr);
    if (native == INVALID_HANDLE_VALUE) {
        return std::unexpected(
            Error{.code = ErrorCode::KeyNotFound,
                  .detail = "key.bin file is missing or corrupted"});
    }
    platform::private_storage::PrivateHandle handle{
        reinterpret_cast<std::intptr_t>(native)};
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (!GetFileInformationByHandleEx(
            native, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes &
         (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY |
          FILE_ATTRIBUTE_DEVICE)) != 0) {
        return std::unexpected(
            Error{.code = ErrorCode::KeyNotFound,
                  .detail = "key.bin file is missing or invalid"});
    }
    while (total < buf.size()) {
        DWORD count = 0;
        if (!ReadFile(native,
                      buf.data() + total,
                      static_cast<DWORD>(buf.size() - total),
                      &count,
                      nullptr)) {
            return std::unexpected(
                Error{.code = ErrorCode::KeyNotFound,
                      .detail = "key.bin file is missing or corrupted"});
        }
        if (count == 0) {
            break;
        }
        total += count;
    }
#else
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return std::unexpected(
            Error{.code = ErrorCode::KeyNotFound,
                  .detail = "key.bin file is missing or invalid"});
    }
    platform::private_storage::PrivateHandle handle{fd};
    struct stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        return std::unexpected(
            Error{.code = ErrorCode::KeyNotFound,
                  .detail = "key.bin file is missing or invalid"});
    }
    while (total < buf.size()) {
        const auto count = ::read(fd, buf.data() + total, buf.size() - total);
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            return std::unexpected(
                Error{.code = ErrorCode::KeyNotFound,
                      .detail = "key.bin file is missing or corrupted"});
        }
        total += static_cast<std::size_t>(count);
    }
#endif
    if (total < key.size()) {
        return std::unexpected(
            Error{.code = ErrorCode::KeyNotFound,
                  .detail = "key.bin file is missing or corrupted"});
    }
    if (total > key.size()) {
        return std::unexpected(
            Error{.code = ErrorCode::KeyInvalid,
                  .detail = "key.bin file has invalid size"});
    }
    std::memcpy(key.data(), buf.data(), key.size());
    obscure(key);
    success = true;
    return key;
}

std::expected<KeyBytes, runtime::Error>
read(const std::filesystem::path& path) {
    return read_impl(path, true);
}

std::expected<KeyBytes, runtime::Error>
read_only(const std::filesystem::path& path) {
    return read_impl(path, false);
}

std::expected<void, runtime::Error> write(const std::filesystem::path& path,
                                          const KeyBytes& clear_key) {
    auto parent =
        platform::private_storage::ensure_directory(path.parent_path());
    if (!parent) {
        return std::unexpected(
            Error{.code = ErrorCode::IoFailure, .detail = parent.error()});
    }
    KeyBytes stored = clear_key;
    obscure(stored);
    const std::string_view bytes{reinterpret_cast<const char*>(stored.data()),
                                 stored.size()};
    auto saved = platform::private_storage::write_atomically(path, bytes);
    crypto_wipe(stored.data(), stored.size());
    if (!saved) {
        return std::unexpected(
            Error{.code = ErrorCode::KeyWriteFailure, .detail = saved.error()});
    }
    return {};
}

std::expected<void, runtime::Error>
write_new(const std::filesystem::path& path,
          const KeyBytes& clear_key,
          platform::private_storage::FileIdentity& identity) {
    identity = {};
    auto parent =
        platform::private_storage::ensure_directory(path.parent_path());
    if (!parent) {
        return std::unexpected(
            Error{.code = ErrorCode::IoFailure, .detail = parent.error()});
    }
    auto file = platform::private_storage::create_private_file(path);
    if (!file) {
        return std::unexpected(Error{
            .code = ErrorCode::KeyWriteFailure,
            .detail = file.error().message,
        });
    }
    identity = file->identity;
    KeyBytes stored = clear_key;
    obscure(stored);
    const auto written = platform::private_storage::write_private_file(
        *file, stored.data(), stored.size());
    crypto_wipe(stored.data(), stored.size());
    if (!written) {
        return std::unexpected(Error{.code = ErrorCode::KeyWriteFailure,
                                     .detail = written.error()});
    }
    auto flushed =
        platform::private_storage::flush_and_close_private_file(*file);
    if (!flushed) {
        return std::unexpected(Error{.code = ErrorCode::KeyWriteFailure,
                                     .detail = flushed.error()});
    }
    auto synced = platform::durability::sync_parent_directory(path);
    if (!synced) {
        return std::unexpected(Error{.code = ErrorCode::KeyWriteFailure,
                                     .detail = synced.error()});
    }
    return {};
}

std::expected<KeyBytes, runtime::Error> derive(std::string_view password,
                                               std::string_view salt_password) {
    if (password.size() < MINIMUM_PASSWORD_SIZE ||
        salt_password.size() < MINIMUM_PASSWORD_SALT_SIZE ||
        password.size() > std::numeric_limits<std::uint32_t>::max() ||
        salt_password.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error{
            .code = ErrorCode::KeyDerivationFailure,
            .detail = "password must be at least 12 characters and salt must "
                      "be at least 16 characters"});
    }
    crypto_argon2_config config = {.algorithm = CRYPTO_ARGON2_ID,
                                   .nb_blocks = ARGON2_MEMORY_BLOCKS,
                                   .nb_passes = ARGON2_PASSES,
                                   .nb_lanes = 1};

    void* work_area = std::malloc(config.nb_blocks * 1024);
    if (!work_area) {
        return std::unexpected(
            Error{.code = ErrorCode::KeyDerivationFailure,
                  .detail = "memory allocation failed in Argon2"});
    }

    crypto_argon2_inputs inputs = {
        .pass = reinterpret_cast<const uint8_t*>(password.data()),
        .salt = reinterpret_cast<const uint8_t*>(salt_password.data()),
        .pass_size = static_cast<uint32_t>(password.size()),
        .salt_size = static_cast<uint32_t>(salt_password.size())};

    KeyBytes key{};
    crypto_argon2(key.data(),
                  KEY_SIZE,
                  work_area,
                  config,
                  inputs,
                  crypto_argon2_no_extras);

    crypto_wipe(work_area, config.nb_blocks * 1024);
    std::free(work_area);
    return key;
}

} // namespace kasumi::runtime::vault
